// Package configparser defines the Parser interface and the domain types shared
// by all AWS config file parser implementations.
package configparser

// DefaultSectionName is the name of the implicit default profile section.
const DefaultSectionName = "default"

// ProfileSection is a profile section of an AWS config file.
type ProfileSection struct {
	Name                    string `ini:"-"`
	MfaSerial               string `ini:"mfa_serial,omitempty"`
	RoleARN                 string `ini:"role_arn,omitempty"`
	ExternalID              string `ini:"external_id,omitempty"`
	Region                  string `ini:"region,omitempty"`
	RoleSessionName         string `ini:"role_session_name,omitempty"`
	DurationSeconds         uint   `ini:"duration_seconds,omitempty"`
	SourceProfile           string `ini:"source_profile,omitempty"`
	IncludeProfile          string `ini:"include_profile,omitempty"`
	SSOSession              string `ini:"sso_session,omitempty"`
	SSOStartURL             string `ini:"sso_start_url,omitempty"`
	SSORegion               string `ini:"sso_region,omitempty"`
	SSOAccountID            string `ini:"sso_account_id,omitempty"`
	SSORoleName             string `ini:"sso_role_name,omitempty"`
	WebIdentityTokenFile    string `ini:"web_identity_token_file,omitempty"`
	WebIdentityTokenProcess string `ini:"web_identity_token_process,omitempty"`
	STSRegionalEndpoints    string `ini:"sts_regional_endpoints,omitempty"`
	EndpointURL             string `ini:"endpoint_url,omitempty"`
	SessionTags             string `ini:"session_tags,omitempty"`
	TransitiveSessionTags   string `ini:"transitive_session_tags,omitempty"`
	SourceIdentity          string `ini:"source_identity,omitempty"`
	CredentialProcess       string `ini:"credential_process,omitempty"`
	MfaProcess              string `ini:"mfa_process,omitempty"`
}

// SSOSessionSection is a [sso-session] section of an AWS config file.
type SSOSessionSection struct {
	Name                  string `ini:"-"`
	SSOStartURL           string `ini:"sso_start_url,omitempty"`
	SSORegion             string `ini:"sso_region,omitempty"`
	SSORegistrationScopes string `ini:"sso_registration_scopes,omitempty"`
}

// IsEmpty reports whether the profile has no meaningful configuration.
func (s ProfileSection) IsEmpty() bool {
	s.Name = ""
	return s == ProfileSection{}
}

// Parser is the interface implemented by all AWS config file parser backends.
// A value is obtained by calling Load; it retains the file path for subsequent
// Save and Add calls.
type Parser interface {
	// Load reads and parses the AWS config file at path.
	Load(path string) error
	// ProfileSections returns all profile sections in declaration order.
	ProfileSections() []ProfileSection
	// ProfileSection returns the named profile section and whether it exists.
	ProfileSection(name string) (ProfileSection, bool)
	// SSOSessionSection returns the named sso-session section and whether it exists.
	SSOSessionSection(name string) (SSOSessionSection, bool)
	// Save writes the current in-memory state back to the file.
	Save() error
	// Add creates or replaces the named profile section and saves the file.
	Add(profile ProfileSection) error
}
