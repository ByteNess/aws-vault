package custom

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteness/aws-vault/v7/vault/configparser"
)

// writeConfig writes content to a temp file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	return path
}

// loadConfig is a shorthand for creating a Parser and calling Load.
func loadConfig(t *testing.T, content string) *Parser {
	t.Helper()
	p := New()
	if err := p.Load(writeConfig(t, content)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return p
}

// --- splitKeyValue ---

func TestSplitKeyValueEquals(t *testing.T) {
	k, v, ok := splitKeyValue("region=us-east-1")
	if !ok || k != "region" || v != "us-east-1" {
		t.Fatalf("got k=%q v=%q ok=%v", k, v, ok)
	}
}

func TestSplitKeyValueColon(t *testing.T) {
	k, v, ok := splitKeyValue("region: us-east-1")
	if !ok || k != "region" || v != "us-east-1" {
		t.Fatalf("got k=%q v=%q ok=%v", k, v, ok)
	}
}

func TestSplitKeyValueLowercasesKey(t *testing.T) {
	k, _, ok := splitKeyValue("Region=us-east-1")
	if !ok || k != "region" {
		t.Fatalf("got k=%q ok=%v", k, ok)
	}
}

func TestSplitKeyValueTrimsKeyWhitespace(t *testing.T) {
	k, v, ok := splitKeyValue("  region  =  us-east-1  ")
	if !ok || k != "region" || v != "us-east-1" {
		t.Fatalf("got k=%q v=%q ok=%v", k, v, ok)
	}
}

func TestSplitKeyValueNoDelimiter(t *testing.T) {
	_, _, ok := splitKeyValue("just-a-word")
	if ok {
		t.Fatal("expected ok=false when no delimiter")
	}
}

func TestSplitKeyValueEmptyKey(t *testing.T) {
	_, _, ok := splitKeyValue("=value")
	if ok {
		t.Fatal("expected ok=false for empty key")
	}
}

func TestSplitKeyValueEmptyValue(t *testing.T) {
	k, v, ok := splitKeyValue("key=")
	if !ok || k != "key" || v != "" {
		t.Fatalf("got k=%q v=%q ok=%v", k, v, ok)
	}
}

// --- stripInlineComment ---

func TestStripInlineCommentNoComment(t *testing.T) {
	if got := stripInlineComment("us-east-1"); got != "us-east-1" {
		t.Fatalf("got %q", got)
	}
}

func TestStripInlineCommentHash(t *testing.T) {
	if got := stripInlineComment("us-east-1 # comment"); got != "us-east-1" {
		t.Fatalf("got %q", got)
	}
}

func TestStripInlineCommentSemicolon(t *testing.T) {
	if got := stripInlineComment("us-east-1 ; comment"); got != "us-east-1" {
		t.Fatalf("got %q", got)
	}
}

func TestStripInlineCommentTabBeforeHashNotStripped(t *testing.T) {
	v := "us-east-1\t#comment"
	if got := stripInlineComment(v); got != v {
		t.Fatalf("got %q, want %q", got, v)
	}
}

func TestStripInlineCommentHashInsideDoubleQuotesPreserved(t *testing.T) {
	if got := stripInlineComment(`"value#with#hashes"`); got != `"value#with#hashes"` {
		t.Fatalf("got %q", got)
	}
}

func TestStripInlineCommentHashAfterClosingQuote(t *testing.T) {
	if got := stripInlineComment(`"value" # comment`); got != `"value"` {
		t.Fatalf("got %q", got)
	}
}

func TestStripInlineCommentPicksEarliest(t *testing.T) {
	if got := stripInlineComment("val ; first # second"); got != "val" {
		t.Fatalf("got %q", got)
	}
}

// --- stripSurroundingQuotes ---

func TestStripSurroundingQuotesDouble(t *testing.T) {
	if got := stripSurroundingQuotes(`"hello"`); got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestStripSurroundingQuotesSingle(t *testing.T) {
	if got := stripSurroundingQuotes("'hello'"); got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestStripSurroundingQuotesMismatch(t *testing.T) {
	v := `"hello'`
	if got := stripSurroundingQuotes(v); got != v {
		t.Fatalf("got %q, want %q (mismatched quotes should not be stripped)", got, v)
	}
}

func TestStripSurroundingQuotesNoQuotes(t *testing.T) {
	if got := stripSurroundingQuotes("hello"); got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestStripSurroundingQuotesTooShort(t *testing.T) {
	if got := stripSurroundingQuotes(`"`); got != `"` {
		t.Fatalf("got %q", got)
	}
}

// --- removeSection ---

func TestRemoveSectionMiddle(t *testing.T) {
	input := []byte("[default]\nregion=us-east-1\n\n[profile foo]\nrole_arn=arn:aws:iam::123:role/foo\n\n[profile bar]\nregion=eu-west-1\n")
	got := removeSection(input, []byte("profile foo"))
	want := []byte("[default]\nregion=us-east-1\n\n[profile bar]\nregion=eu-west-1\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRemoveSectionLast(t *testing.T) {
	input := []byte("[default]\nregion=us-east-1\n\n[profile foo]\nrole_arn=arn:aws:iam::123:role/foo\n")
	got := removeSection(input, []byte("profile foo"))
	want := []byte("[default]\nregion=us-east-1\n\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRemoveSectionNotFound(t *testing.T) {
	input := []byte("[default]\nregion=us-east-1\n")
	got := removeSection(input, []byte("profile nonexistent"))
	if !bytes.Equal(got, input) {
		t.Fatalf("got:\n%s\nwant:\n%s (unchanged)", got, input)
	}
}

func TestRemoveSectionPreservesIndentedSubProperties(t *testing.T) {
	input := []byte("[profile keep]\nregion=us-east-1\n\n[profile remove]\nrole_arn=arn:aws:iam::123:role/r\n  services=s3\n\n[profile keep2]\nregion=eu-west-1\n")
	got := removeSection(input, []byte("profile remove"))
	want := []byte("[profile keep]\nregion=us-east-1\n\n[profile keep2]\nregion=eu-west-1\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRemoveSectionPreservesCRLF(t *testing.T) {
	input := []byte("[default]\r\nregion=us-east-1\r\n\r\n[profile foo]\r\nrole_arn=arn:aws:iam::123:role/foo\r\n\r\n[profile bar]\r\nregion=eu-west-1\r\n")
	got := removeSection(input, []byte("profile foo"))
	want := []byte("[default]\r\nregion=us-east-1\r\n\r\n[profile bar]\r\nregion=eu-west-1\r\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("CRLF line endings not preserved.\ngot (hex):\n%x\nwant (hex):\n%x", got, want)
	}
}

// --- mapFromProfileSection ---

func TestMapFromProfileSectionOmitsEmptyFields(t *testing.T) {
	p := configparser.ProfileSection{Name: "myprofile", Region: "us-east-1"}
	kv := mapFromProfileSection(p)
	if _, ok := kv["mfa_serial"]; ok {
		t.Fatal("empty fields should be omitted from map")
	}
	if kv["region"] != "us-east-1" {
		t.Fatalf("expected region=us-east-1, got %q", kv["region"])
	}
}

func TestMapFromProfileSectionDurationSeconds(t *testing.T) {
	p := configparser.ProfileSection{Name: "p", DurationSeconds: 3600}
	kv := mapFromProfileSection(p)
	if kv["duration_seconds"] != "3600" {
		t.Fatalf("expected duration_seconds=3600, got %q", kv["duration_seconds"])
	}
}

func TestMapFromProfileSectionZeroDurationOmitted(t *testing.T) {
	p := configparser.ProfileSection{Name: "p", DurationSeconds: 0}
	kv := mapFromProfileSection(p)
	if _, ok := kv["duration_seconds"]; ok {
		t.Fatal("zero DurationSeconds should be omitted")
	}
}

// --- sectionOrder consistency after overwrite ---

func TestSectionOrderAfterOverwrite(t *testing.T) {
	// Start with two profiles.
	parser := &Parser{}
	parser.sections = map[string]map[string]string{
		"profile a": {"region": "us-east-1"},
		"profile b": {"region": "eu-west-1"},
	}
	parser.sectionOrder = []string{"profile a", "profile b"}
	parser.rawBytes = []byte("[profile a]\nregion=us-east-1\n\n[profile b]\nregion=eu-west-1\n")
	parser.path = t.TempDir() + "/config"

	// Overwrite profile a.
	if err := parser.Add(configparser.ProfileSection{Name: "a", Region: "ap-southeast-1"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// profile a should now be last in sectionOrder (moved to tail like rawBytes).
	order := parser.sectionOrder
	if len(order) != 2 {
		t.Fatalf("expected 2 sections, got %v", order)
	}
	if order[0] != "profile b" || order[1] != "profile a" {
		t.Fatalf("expected [profile b, profile a], got %v", order)
	}
}

// ---------------------------------------------------------------------------
// Multi-line continuation value parsing (botocore compatibility)
// ---------------------------------------------------------------------------
//
// Python configparser (used by botocore) treats any line that begins with
// whitespace as a continuation of the previous key's value. The continuation
// line has its leading whitespace stripped and is appended to the current
// value with a "\n" separator. aws-vault's custom parser must match this
// so that multi-line credential_process / web_identity_token_process values
// round-trip correctly.

// TestContinuationSpaceIndent verifies that a space-indented continuation
// line is appended to the previous key's value.
func TestContinuationSpaceIndent(t *testing.T) {
	p := loadConfig(t, "[profile foo]\ncredential_process = /usr/bin/aws-vault\n  exec prod\n")
	prof, ok := p.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found")
	}
	want := "/usr/bin/aws-vault\nexec prod"
	if prof.CredentialProcess != want {
		t.Fatalf("got %q, want %q", prof.CredentialProcess, want)
	}
}

// TestContinuationTabIndent verifies that a tab-indented continuation line
// is treated identically to a space-indented one.
func TestContinuationTabIndent(t *testing.T) {
	p := loadConfig(t, "[profile foo]\ncredential_process = /usr/bin/aws-vault\n\texec prod\n")
	prof, ok := p.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found")
	}
	want := "/usr/bin/aws-vault\nexec prod"
	if prof.CredentialProcess != want {
		t.Fatalf("got %q, want %q", prof.CredentialProcess, want)
	}
}

// TestContinuationMultipleLines verifies that several continuation lines are
// all appended, each separated by "\n".
func TestContinuationMultipleLines(t *testing.T) {
	p := loadConfig(t, "[profile foo]\ncredential_process = /usr/bin/aws-vault\n  exec prod\n  --duration=1h\n")
	prof, ok := p.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found")
	}
	want := "/usr/bin/aws-vault\nexec prod\n--duration=1h"
	if prof.CredentialProcess != want {
		t.Fatalf("got %q, want %q", prof.CredentialProcess, want)
	}
}

// TestContinuationStopsAtBlankLine verifies that a blank line terminates the
// continuation (matching Python configparser semantics).
func TestContinuationStopsAtBlankLine(t *testing.T) {
	p := loadConfig(t, "[profile foo]\ncredential_process = /usr/bin/aws-vault\n\nexec prod\n")
	prof, ok := p.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found")
	}
	// blank line resets continuation; "exec prod" (no indent) is not a valid
	// key=value line, so it is ignored, not appended.
	want := "/usr/bin/aws-vault"
	if prof.CredentialProcess != want {
		t.Fatalf("got %q, want %q", prof.CredentialProcess, want)
	}
}

// TestContinuationStopsAtNextSection verifies that a section header terminates
// the continuation and the following key belongs to the new section.
func TestContinuationStopsAtNextSection(t *testing.T) {
	p := loadConfig(t, "[profile foo]\ncredential_process = /usr/bin/aws-vault\n  exec foo\n\n[profile bar]\nregion = eu-west-1\n")
	foo, ok := p.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found")
	}
	if foo.CredentialProcess != "/usr/bin/aws-vault\nexec foo" {
		t.Fatalf("foo.credential_process = %q", foo.CredentialProcess)
	}
	bar, ok := p.ProfileSection("bar")
	if !ok {
		t.Fatal("profile bar not found")
	}
	if bar.Region != "eu-west-1" {
		t.Fatalf("bar.region = %q", bar.Region)
	}
	// continuation must not bleed into bar
	if bar.CredentialProcess != "" {
		t.Fatalf("bar.credential_process should be empty, got %q", bar.CredentialProcess)
	}
}

// TestContinuationDoesNotAffectOtherKeys verifies that only the immediately
// preceding key is extended; subsequent keys in the same section are
// unaffected.
func TestContinuationDoesNotAffectOtherKeys(t *testing.T) {
	p := loadConfig(t, "[profile foo]\ncredential_process = /usr/bin/aws-vault\n  exec foo\nregion = us-east-1\n")
	prof, ok := p.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found")
	}
	if prof.CredentialProcess != "/usr/bin/aws-vault\nexec foo" {
		t.Fatalf("credential_process = %q", prof.CredentialProcess)
	}
	if prof.Region != "us-east-1" {
		t.Fatalf("region = %q", prof.Region)
	}
}

// TestContinuationSubsectionPattern verifies that the botocore subsection
// pattern (key on its own, value entirely in indented lines) produces a raw
// string starting with "\n", matching what Python configparser returns before
// botocore's _parse_nested step.
func TestContinuationSubsectionPattern(t *testing.T) {
	// aws-vault does not use nested service config, but the raw value must
	// survive in sections so Save() round-trips are stable.
	p := loadConfig(t, "[profile foo]\nregion = us-east-1\ns3 =\n  endpoint_url = https://s3.example.com\n  addressing_style = path\n")
	prof, ok := p.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found")
	}
	if prof.Region != "us-east-1" {
		t.Fatalf("region = %q", prof.Region)
	}
	// "s3" is not a ProfileSection field; verify it is stored in sections map
	// as the raw continuation string starting with "\n".
	raw := p.sections["profile foo"]["s3"]
	if len(raw) == 0 || raw[0] != '\n' {
		t.Fatalf("s3 raw value should start with newline, got %q", raw)
	}
	if raw != "\nendpoint_url = https://s3.example.com\naddressing_style = path" {
		t.Fatalf("s3 raw value = %q", raw)
	}
}

// TestContinuationPreservedInRawBytes verifies that rawBytes is unchanged by
// the logical parsing of continuation lines — the original file content is
// preserved for lossless Save().
func TestContinuationPreservedInRawBytes(t *testing.T) {
	content := "[profile foo]\ncredential_process = /usr/bin/aws-vault\n  exec prod\n"
	p := loadConfig(t, content)
	if !bytes.Equal(p.rawBytes, []byte(content)) {
		t.Fatalf("rawBytes mutated during load;\ngot:  %q\nwant: %q", p.rawBytes, content)
	}
}

// TestContinuationNotExtendedPastMalformedLine verifies that a non-indented
// line that fails key=value parsing (no delimiter) resets the active
// continuation, so the indented line that follows does not spuriously extend
// the previous key.
func TestContinuationNotExtendedPastMalformedLine(t *testing.T) {
	p := loadConfig(t, "[profile foo]\ncredential_process = /usr/bin/aws-vault\nJUNK\n  this-must-not-append\n")
	prof, ok := p.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found")
	}
	if prof.CredentialProcess != "/usr/bin/aws-vault" {
		t.Fatalf("got %q, want %q", prof.CredentialProcess, "/usr/bin/aws-vault")
	}
}

// --- B2: Add() must quote values containing inline-comment markers ---

// TestAddRoundTripValueWithCommentMarker verifies that a value containing
// " # " survives an Add() → re-Load() round-trip intact.  Without quoting,
// stripInlineComment would truncate the value on the next Load().
func TestAddRoundTripValueWithCommentMarker(t *testing.T) {
	p := loadConfig(t, "[profile foo]\nregion=us-east-1\n")

	credProcess := "/usr/bin/wrapper --flag1 # not-a-comment"
	if err := p.Add(configparser.ProfileSection{
		Name:              "foo",
		Region:            "us-east-1",
		CredentialProcess: credProcess,
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	p2 := New()
	if err := p2.Load(p.path); err != nil {
		t.Fatalf("re-Load: %v", err)
	}
	prof, ok := p2.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found after round-trip")
	}
	if prof.CredentialProcess != credProcess {
		t.Fatalf("credential_process = %q, want %q", prof.CredentialProcess, credProcess)
	}
}

// TestAddRoundTripValueWithSemicolonCommentMarker verifies the same for " ; ".
func TestAddRoundTripValueWithSemicolonCommentMarker(t *testing.T) {
	p := loadConfig(t, "[profile foo]\nregion=us-east-1\n")

	credProcess := "/usr/bin/wrapper --opt=val ; side-note"
	if err := p.Add(configparser.ProfileSection{
		Name:              "foo",
		Region:            "us-east-1",
		CredentialProcess: credProcess,
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	p2 := New()
	if err := p2.Load(p.path); err != nil {
		t.Fatalf("re-Load: %v", err)
	}
	prof, ok := p2.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found after round-trip")
	}
	if prof.CredentialProcess != credProcess {
		t.Fatalf("credential_process = %q, want %q", prof.CredentialProcess, credProcess)
	}
}

// --- B3: Add() must roll back in-memory state when Save() fails ---

// TestAddRollsBackOnSaveFailure verifies that when Save() fails (because the
// path is in a non-existent directory), Add() leaves rawBytes, sectionOrder,
// and sections exactly as they were before the call.
func TestAddRollsBackOnSaveFailure(t *testing.T) {
	p := &Parser{
		path:     "/nonexistent-dir-for-test/config",
		rawBytes: []byte("[profile foo]\nregion=us-east-1\n"),
		sections: map[string]map[string]string{
			"profile foo": {"region": "us-east-1"},
		},
		sectionOrder: []string{"profile foo"},
	}

	origBytes := make([]byte, len(p.rawBytes))
	copy(origBytes, p.rawBytes)
	origOrder := append([]string{}, p.sectionOrder...)

	err := p.Add(configparser.ProfileSection{Name: "bar", Region: "eu-west-1"})
	if err == nil {
		t.Fatal("expected Add() to fail with non-existent path")
	}

	if !bytes.Equal(p.rawBytes, origBytes) {
		t.Fatalf("rawBytes not rolled back after failed Save();\ngot:  %q\nwant: %q", p.rawBytes, origBytes)
	}
	if len(p.sectionOrder) != len(origOrder) {
		t.Fatalf("sectionOrder not rolled back: %v", p.sectionOrder)
	}
	if _, exists := p.sections["profile bar"]; exists {
		t.Fatal("sections[\"profile bar\"] still present after failed Save()")
	}
}

// --- A3: SSOSessionSection must be reflection-driven ---

// TestSSOSessionSectionAllFieldsRoundTrip verifies that all ini-tagged fields
// of SSOSessionSection are populated correctly.  This test passes before and
// after the A3 refactor; it guards against a regression when new fields are
// added to SSOSessionSection — hardcoded assignments would silently miss them.
func TestSSOSessionSectionAllFieldsRoundTrip(t *testing.T) {
	p := loadConfig(t, "[sso-session dev]\nsso_start_url=https://my-sso.awsapps.com/start\nsso_region=us-east-1\nsso_registration_scopes=sso:account:access\n")
	s, ok := p.SSOSessionSection("dev")
	if !ok {
		t.Fatal("sso-session dev not found")
	}
	if s.SSOStartURL != "https://my-sso.awsapps.com/start" {
		t.Fatalf("SSOStartURL = %q", s.SSOStartURL)
	}
	if s.SSORegion != "us-east-1" {
		t.Fatalf("SSORegion = %q", s.SSORegion)
	}
	if s.SSORegistrationScopes != "sso:account:access" {
		t.Fatalf("SSORegistrationScopes = %q", s.SSORegistrationScopes)
	}
}

// TestAddRoundTripMultilineValue verifies that a profile containing a
// multi-line credential_process survives an Add() → re-Load() round-trip
// with the full value intact. This guards against Add() writing continuation
// lines without indentation, which would cause the second line to be silently
// dropped on the next Load().
func TestAddRoundTripMultilineValue(t *testing.T) {
	content := "[profile foo]\ncredential_process = /usr/bin/aws-vault\n  exec prod\n"
	p := loadConfig(t, content)

	prof, ok := p.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found")
	}
	wantCP := "/usr/bin/aws-vault\nexec prod"
	if prof.CredentialProcess != wantCP {
		t.Fatalf("initial load: credential_process = %q, want %q", prof.CredentialProcess, wantCP)
	}

	// Update an unrelated field and re-write the profile via Add().
	prof.Region = "us-east-1"
	if err := p.Add(prof); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Re-load from the file Add() wrote and verify the multi-line value survived.
	p2 := New()
	if err := p2.Load(p.path); err != nil {
		t.Fatalf("re-Load: %v", err)
	}
	prof2, ok := p2.ProfileSection("foo")
	if !ok {
		t.Fatal("profile foo not found after round-trip")
	}
	if prof2.CredentialProcess != wantCP {
		t.Fatalf("after round-trip: credential_process = %q, want %q", prof2.CredentialProcess, wantCP)
	}
	if prof2.Region != "us-east-1" {
		t.Fatalf("after round-trip: region = %q", prof2.Region)
	}
}
