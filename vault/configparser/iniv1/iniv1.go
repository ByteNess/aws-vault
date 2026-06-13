// Package iniv1 implements configparser.Parser using gopkg.in/ini.v1.
package iniv1

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/byteness/aws-vault/v7/vault/configparser"
	ini "gopkg.in/ini.v1"
)

// Parser implements configparser.Parser using gopkg.in/ini.v1.
type Parser struct {
	path    string
	iniFile *ini.File
}

// prettyFormatOnce guards the single write to ini.PrettyFormat, which is a
// package-level variable in gopkg.in/ini.v1. Concurrent Load() calls would
// race on it without this guard.
var prettyFormatOnce sync.Once

// New returns a new ini.v1-backed Parser.
func New() *Parser {
	prettyFormatOnce.Do(func() { ini.PrettyFormat = false })
	return &Parser{}
}

func (p *Parser) Load(path string) error {
	p.path = path
	f, err := ini.LoadSources(ini.LoadOptions{
		AllowNestedValues:        true,
		InsensitiveSections:      false,
		InsensitiveKeys:          true,
		SpaceBeforeInlineComment: true,
	}, path)
	if err != nil {
		return err
	}
	p.iniFile = f
	return nil
}

func (p *Parser) ProfileSections() []configparser.ProfileSection {
	result := []configparser.ProfileSection{}
	for _, section := range p.iniFile.SectionStrings() {
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
	sectionName := "profile " + name
	if name == configparser.DefaultSectionName {
		sectionName = configparser.DefaultSectionName
	}
	section, err := p.iniFile.GetSection(sectionName)
	if err != nil {
		return profile, false
	}
	if err = section.MapTo(&profile); err != nil {
		log.Printf("Failed to map ini section %q to profile: %v", sectionName, err)
		return profile, false
	}
	return profile, true
}

func (p *Parser) SSOSessionSection(name string) (configparser.SSOSessionSection, bool) {
	ssoSession := configparser.SSOSessionSection{Name: name}
	section, err := p.iniFile.GetSection("sso-session " + name)
	if err != nil {
		return ssoSession, false
	}
	if err = section.MapTo(&ssoSession); err != nil {
		log.Printf("Failed to map ini section %q to sso-session: %v", "sso-session "+name, err)
		return ssoSession, false
	}
	return ssoSession, true
}

func (p *Parser) Save() error {
	return p.iniFile.SaveTo(p.path)
}

func (p *Parser) Add(profile configparser.ProfileSection) error {
	sectionName := "profile " + profile.Name
	if profile.Name == configparser.DefaultSectionName {
		sectionName = configparser.DefaultSectionName
	}
	section, err := p.iniFile.NewSection(sectionName)
	if err != nil {
		return fmt.Errorf("creating section %q: %w", profile.Name, err)
	}
	if err = section.ReflectFrom(&profile); err != nil {
		return fmt.Errorf("mapping profile to ini section: %w", err)
	}
	return p.Save()
}
