// Package custom implements configparser.Parser using a single-pass bufio.Scanner.
// It is activated by setting AWS_VAULT_USE_CUSTOM_INI_PARSER=true (or 1).
package custom

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/byteness/aws-vault/v7/vault/configparser"
)

// Parser implements configparser.Parser with a custom bufio.Scanner backend.
type Parser struct {
	path         string
	rawBytes     []byte
	sections     map[string]map[string]string
	sectionOrder []string
}

// New returns a new custom Parser.
func New() *Parser { return &Parser{} }

func (p *Parser) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}
	p.path = path
	p.rawBytes = data
	// Pre-size to reduce rehashing; ~150 bytes per section on average.
	p.sections = make(map[string]map[string]string, len(data)/150+4)
	p.sectionOrder = nil

	var current map[string]string
	var lastKey string // most recently parsed key; tracks active continuation

	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Raise the per-line limit to 1 MiB. The default 64 KiB can be exceeded
	// by long credential_process or web_identity_token_process values.
	// Use a small initial buffer (4 KiB) so small files don't pay for the
	// large max-size allocation.
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// Continuation line: begins with whitespace and a key is active.
		// Matching Python configparser / botocore semantics: strip leading
		// whitespace and append to the current key's value with "\n".
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if current != nil && lastKey != "" {
				if cont := strings.TrimSpace(line); cont != "" {
					current[lastKey] = current[lastKey] + "\n" + cont
				}
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';' {
			lastKey = "" // blank/comment terminates any active continuation
			continue
		}
		if trimmed[0] == '[' {
			current = p.openSection(trimmed)
			lastKey = ""
			continue
		}
		if current == nil {
			continue
		}
		if k, v, ok := splitKeyValue(trimmed); ok {
			current[k] = v
			lastKey = k
		} else {
			lastKey = "" // malformed line terminates any active continuation
		}
	}
	return scanner.Err()
}

// openSection parses a section header line (e.g. "[profile foo] # comment"),
// registers the section if it has not been seen before, and returns its
// key-value map. Section names are taken verbatim between '[' and the last ']';
// inner whitespace is preserved to match ini.v1 behaviour.
func (p *Parser) openSection(line string) map[string]string {
	closeIdx := strings.LastIndex(line, "]")
	if closeIdx < 0 {
		return nil
	}
	name := line[1:closeIdx]
	if m, ok := p.sections[name]; ok {
		return m // duplicate section — reuse map so keys are merged
	}
	m := make(map[string]string, 8)
	p.sections[name] = m
	p.sectionOrder = append(p.sectionOrder, name)
	return m
}

// splitKeyValue parses a "key=value" or "key: value" line into a lowercased,
// trimmed key and a processed value. Returns ok=false when no delimiter is
// found or the key is empty.
func splitKeyValue(line string) (key, val string, ok bool) {
	sepIdx := strings.IndexAny(line, "=:")
	if sepIdx < 0 {
		return "", "", false
	}
	key = strings.ToLower(strings.TrimSpace(line[:sepIdx]))
	if key == "" {
		return "", "", false
	}
	val = stripInlineComment(strings.TrimSpace(line[sepIdx+1:]))
	val = stripSurroundingQuotes(val)
	return key, val, true
}

// stripInlineComment removes a trailing comment from a value. Only " #" or
// " ;" (literal space before the marker) trigger stripping — a tab does not —
// matching ini.v1's SpaceBeforeInlineComment behaviour. When the value begins
// with a quote, comment markers inside the quoted region are skipped.
func stripInlineComment(v string) string {
	searchFrom := 0
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		if closing := strings.IndexByte(v[1:], v[0]); closing >= 0 {
			searchFrom = closing + 2
		}
	}
	cutAt := -1
	for _, marker := range []string{" #", " ;"} {
		if i := strings.Index(v[searchFrom:], marker); i >= 0 {
			if pos := searchFrom + i; cutAt < 0 || pos < cutAt {
				cutAt = pos
			}
		}
	}
	if cutAt < 0 {
		return v
	}
	return strings.TrimRight(v[:cutAt], " \t")
}

// stripSurroundingQuotes removes a matching outer '"' or '\” pair, matching
// ini.v1's PreserveSurroundedQuote=false default.
func stripSurroundingQuotes(v string) string {
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		return v[1 : len(v)-1]
	}
	return v
}

func (p *Parser) ProfileSections() []configparser.ProfileSection {
	result := []configparser.ProfileSection{}
	if p.sections == nil {
		return result
	}
	for _, section := range p.sectionOrder {
		if section == configparser.DefaultSectionName || strings.HasPrefix(section, "profile ") {
			profile, _ := p.ProfileSection(strings.TrimPrefix(section, "profile "))
			if section == configparser.DefaultSectionName && profile.IsEmpty() {
				continue
			}
			result = append(result, profile)
		} else if strings.HasPrefix(section, "sso-session ") || strings.HasPrefix(section, "services ") {
			continue
		} else {
			log.Printf("Unrecognised ini file section: %s", section)
		}
	}
	return result
}

func (p *Parser) ProfileSection(name string) (configparser.ProfileSection, bool) {
	profile := configparser.ProfileSection{Name: name}
	if p.sections == nil {
		return profile, false
	}
	sectionName := "profile " + name
	if name == configparser.DefaultSectionName {
		sectionName = configparser.DefaultSectionName
	}
	kv, ok := p.sections[sectionName]
	if !ok {
		return profile, false
	}
	mapToProfileSection(kv, &profile)
	return profile, true
}

// mapToProfileSection is the inverse of mapFromProfileSection: it populates a
// ProfileSection from a key-value map using ini struct tags. Both functions use
// the same tag-driven dispatch so adding a field to ProfileSection keeps them
// in sync automatically.
func mapToProfileSection(kv map[string]string, p *configparser.ProfileSection) {
	t := reflect.TypeOf(p).Elem()
	v := reflect.ValueOf(p).Elem()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("ini")
		if tag == "" || tag == "-" {
			continue
		}
		key := strings.SplitN(tag, ",", 2)[0]
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			fv.SetString(kv[key])
		case reflect.Uint:
			if s := kv[key]; s != "" {
				if n, err := strconv.ParseUint(s, 10, 64); err == nil {
					fv.SetUint(n)
				}
			}
		}
	}
}

// mapToSSOSessionSection populates s from kv using ini struct tags, mirroring
// mapToProfileSection. Any new field added to SSOSessionSection is handled
// automatically as long as it carries an ini tag.
func mapToSSOSessionSection(kv map[string]string, s *configparser.SSOSessionSection) {
	t := reflect.TypeOf(s).Elem()
	v := reflect.ValueOf(s).Elem()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("ini")
		if tag == "" || tag == "-" {
			continue
		}
		key := strings.SplitN(tag, ",", 2)[0]
		fv := v.Field(i)
		if fv.Kind() == reflect.String {
			fv.SetString(kv[key])
		}
	}
}

func (p *Parser) SSOSessionSection(name string) (configparser.SSOSessionSection, bool) {
	ssoSession := configparser.SSOSessionSection{Name: name}
	if p.sections == nil {
		return ssoSession, false
	}
	kv, ok := p.sections["sso-session "+name]
	if !ok {
		return ssoSession, false
	}
	mapToSSOSessionSection(kv, &ssoSession)
	return ssoSession, true
}

func (p *Parser) Save() error {
	// Write to a temp file in the same directory, then rename over the target.
	// POSIX rename(2) is atomic, so readers always see either the old or new
	// file — never a partially-written one.
	dir := filepath.Dir(p.path)
	tmp, err := os.CreateTemp(dir, ".aws-config-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file for atomic save: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup: Remove is a no-op after a successful Rename.
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(p.rawBytes); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, p.path); err != nil {
		return fmt.Errorf("renaming temp file to %s: %w", p.path, err)
	}
	return nil
}

// removeSection excises the named section from raw config bytes. It removes
// the section header and all lines up to (but not including) the next header.
// Returns data unchanged if the section is not found. Original line endings
// (LF or CRLF) are preserved verbatim.
func removeSection(data []byte, name []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(data))
	skip := false
	rest := data
	for len(rest) > 0 {
		nl := bytes.IndexByte(rest, '\n')
		var raw []byte
		if nl < 0 {
			raw = rest
			rest = nil
		} else {
			raw = rest[:nl+1]
			rest = rest[nl+1:]
		}
		// Strip line ending for analysis only; raw is written as-is.
		content := bytes.TrimRight(raw, "\r\n")
		trimmed := bytes.TrimSpace(content)
		if skip {
			if len(trimmed) > 0 && trimmed[0] == '[' {
				skip = false
			} else {
				continue
			}
		}
		if len(trimmed) > 0 && trimmed[0] == '[' {
			closeIdx := bytes.LastIndexByte(trimmed, ']')
			if closeIdx > 0 && bytes.Equal(trimmed[1:closeIdx], name) {
				skip = true
				continue
			}
		}
		out.Write(raw)
	}
	return out.Bytes()
}

// mapFromProfileSection builds a key-value map from a ProfileSection using ini struct tags.
func mapFromProfileSection(prof configparser.ProfileSection) map[string]string {
	kv := make(map[string]string, 8)
	t := reflect.TypeOf(prof)
	v := reflect.ValueOf(prof)
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("ini")
		if tag == "" || tag == "-" {
			continue
		}
		key := strings.SplitN(tag, ",", 2)[0]
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			if s := fv.String(); s != "" {
				kv[key] = s
			}
		case reflect.Uint:
			if n := fv.Uint(); n > 0 {
				kv[key] = strconv.FormatUint(n, 10)
			}
		}
	}
	return kv
}

func (p *Parser) Add(profile configparser.ProfileSection) error {
	sectionName := "profile " + profile.Name
	if profile.Name == configparser.DefaultSectionName {
		sectionName = configparser.DefaultSectionName
	}

	// Snapshot in-memory state so we can roll back if Save() fails.
	prevRawBytes := make([]byte, len(p.rawBytes))
	copy(prevRawBytes, p.rawBytes)
	prevSectionOrder := append([]string{}, p.sectionOrder...)
	prevKV, hadSection := p.sections[sectionName]

	// Remove existing block to prevent unbounded file growth on update.
	if p.sections != nil {
		if _, exists := p.sections[sectionName]; exists {
			p.rawBytes = removeSection(p.rawBytes, []byte(sectionName))
			// Remove from sectionOrder so it gets re-appended at the tail,
			// keeping in-memory order consistent with rawBytes position.
			for i, s := range p.sectionOrder {
				if s == sectionName {
					p.sectionOrder = append(p.sectionOrder[:i], p.sectionOrder[i+1:]...)
					break
				}
			}
		}
	}
	kv := mapFromProfileSection(profile)
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf strings.Builder
	buf.WriteString("\n[")
	buf.WriteString(sectionName)
	buf.WriteString("]\n")
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte('=')
		val := strings.ReplaceAll(kv[k], "\n", "\n\t")
		// Quote single-line values that contain inline-comment markers so they
		// are not truncated by stripInlineComment on the next Load().
		if needsQuoting(val) {
			buf.WriteByte('"')
			buf.WriteString(val)
			buf.WriteByte('"')
		} else {
			buf.WriteString(val)
		}
		buf.WriteByte('\n')
	}
	p.rawBytes = append(p.rawBytes, []byte(buf.String())...)
	if p.sections == nil {
		p.sections = make(map[string]map[string]string)
	}
	p.sectionOrder = append(p.sectionOrder, sectionName)
	p.sections[sectionName] = kv

	if err := p.Save(); err != nil {
		// Roll back all in-memory mutations so the caller sees a consistent state.
		p.rawBytes = prevRawBytes
		p.sectionOrder = prevSectionOrder
		if hadSection {
			p.sections[sectionName] = prevKV
		} else {
			delete(p.sections, sectionName)
		}
		return err
	}
	return nil
}

// needsQuoting reports whether v must be wrapped in double quotes when
// serialized to file. Only single-line values are quoted; continuation lines
// in multi-line values are indented and are not subject to inline-comment
// stripping on Load().
func needsQuoting(v string) bool {
	if strings.ContainsRune(v, '\n') {
		return false
	}
	return (strings.Contains(v, " #") || strings.Contains(v, " ;")) &&
		!strings.Contains(v, `"`)
}
