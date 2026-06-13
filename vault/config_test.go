package vault_test

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
	"github.com/google/go-cmp/cmp"
)

// see http://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html
var exampleConfig = []byte(`# an example profile file
[default]
region=us-west-2
output=json

[profile user2]
REGION=us-east-1
output=text

[profile withsource]
source_profile=user2
region=us-east-1

[profile withMFA]
source_profile=user2
Role_Arn=arn:aws:iam::4451234513441615400570:role/aws_admin
mfa_Serial=arn:aws:iam::1234513441:mfa/blah
Region=us-east-1
duration_seconds=1200
sts_regional_endpoints=legacy

[profile withendpointurl]
region=us-east-1
endpoint_url=https://localhost:1234

[profile testincludeprofile1]
region=us-east-1

[profile testincludeprofile2]
include_profile=testincludeprofile1

[profile with-sso-session]
sso_session = moon-sso
sso_account_id=123456
region = moon-1 # Different from sso region

[sso-session moon-sso]
sso_start_url = https://d-123456789.example.com/start
sso_region = moon-2  # Different from profile region
sso_registration_scopes = sso:account:access
`)

var nestedConfig = []byte(`[default]

[profile testing]
aws_access_key_id=foo
aws_secret_access_key=bar
region=us-west-2
s3=
  max_concurrent_requests=10
  max_queue_size=1000
`)

var defaultsOnlyConfigWithHeader = []byte(`[default]
region=us-west-2
output=json
`)

func newConfigFile(t testing.TB, b []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", "aws-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.Name(), b, 0600); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestProfileNameCaseSensitivity(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	def, ok := cfg.ProfileSection("withMFA")
	if !ok {
		t.Fatalf("Expected to match profile withMFA")
	}

	expectedMfaSerial := "arn:aws:iam::1234513441:mfa/blah"
	if def.MfaSerial != expectedMfaSerial {
		t.Fatalf("Expected %s, got %s", expectedMfaSerial, def.MfaSerial)
	}
}

func TestConfigParsingProfiles(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	var testCases = []struct {
		expected vault.ProfileSection
		ok       bool
	}{
		{vault.ProfileSection{Name: "user2", Region: "us-east-1"}, true},
		{vault.ProfileSection{Name: "withsource", SourceProfile: "user2", Region: "us-east-1"}, true},
		{vault.ProfileSection{Name: "withMFA", MfaSerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", DurationSeconds: 1200, SourceProfile: "user2", STSRegionalEndpoints: "legacy"}, true},
		{vault.ProfileSection{Name: "withendpointurl", Region: "us-east-1", EndpointURL: "https://localhost:1234"}, true},
		{vault.ProfileSection{Name: "nopenotthere"}, false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("profile_%s", tc.expected.Name), func(t *testing.T) {
			actual, ok := cfg.ProfileSection(tc.expected.Name)
			if ok != tc.ok {
				t.Fatalf("Expected second param to be %v, got %v", tc.ok, ok)
			}
			if diff := cmp.Diff(tc.expected, actual); diff != "" {
				t.Errorf("ProfileSection() mismatch (-expected +actual):\n%s", diff)
			}
		})
	}
}

func TestConfigParsingDefault(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	def, ok := cfg.ProfileSection("default")
	if !ok {
		t.Fatalf("Expected to find default profile")
	}

	expected := vault.ProfileSection{
		Name:   "default",
		Region: "us-west-2",
	}

	if !reflect.DeepEqual(def, expected) {
		t.Fatalf("Expected %+v, got %+v", expected, def)
	}
}

func TestProfilesFromConfig(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	expected := []vault.ProfileSection{
		{Name: "default", Region: "us-west-2"},
		{Name: "user2", Region: "us-east-1"},
		{Name: "withsource", Region: "us-east-1", SourceProfile: "user2"},
		{Name: "withMFA", MfaSerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", DurationSeconds: 1200, SourceProfile: "user2", STSRegionalEndpoints: "legacy"},
		{Name: "withendpointurl", Region: "us-east-1", EndpointURL: "https://localhost:1234"},
		{Name: "testincludeprofile1", Region: "us-east-1"},
		{Name: "testincludeprofile2", IncludeProfile: "testincludeprofile1"},
		{Name: "with-sso-session", SSOSession: "moon-sso", Region: "moon-1", SSOAccountID: "123456"},
	}
	actual := cfg.ProfileSections()

	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("ProfileSections() mismatch (-expected +actual):\n%s", diff)
	}
}

func TestAddProfileToExistingConfig(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Add(vault.ProfileSection{
		Name:          "llamas",
		MfaSerial:     "testserial",
		Region:        "us-east-1",
		SourceProfile: "default",
	})
	if err != nil {
		t.Fatalf("Error adding profile: %#v", err)
	}

	expected := []vault.ProfileSection{
		{Name: "default", Region: "us-west-2"},
		{Name: "user2", Region: "us-east-1"},
		{Name: "withsource", Region: "us-east-1", SourceProfile: "user2"},
		{Name: "withMFA", MfaSerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", DurationSeconds: 1200, SourceProfile: "user2", STSRegionalEndpoints: "legacy"},
		{Name: "withendpointurl", Region: "us-east-1", EndpointURL: "https://localhost:1234"},
		{Name: "testincludeprofile1", Region: "us-east-1"},
		{Name: "testincludeprofile2", IncludeProfile: "testincludeprofile1"},
		{Name: "with-sso-session", SSOSession: "moon-sso", Region: "moon-1", SSOAccountID: "123456"},
		{Name: "llamas", MfaSerial: "testserial", Region: "us-east-1", SourceProfile: "default"},
	}
	actual := cfg.ProfileSections()

	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("ProfileSections() mismatch (-expected +actual):\n%s", diff)
	}
}

func TestAddProfileToExistingNestedConfig(t *testing.T) {
	f := newConfigFile(t, nestedConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Add(vault.ProfileSection{
		Name:      "llamas",
		MfaSerial: "testserial",
		Region:    "us-east-1",
	})
	if err != nil {
		t.Fatalf("Error adding profile: %#v", err)
	}

	expected := append(nestedConfig, []byte(
		"\n[profile llamas]\nmfa_serial=testserial\nregion=us-east-1\n",
	)...)

	b, _ := os.ReadFile(f)

	if !bytes.Equal(expected, b) {
		t.Fatalf("Expected:\n%q\nGot:\n%q", expected, b)
	}
}

func TestIncludeProfile(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	configLoader := &vault.ConfigLoader{File: configFile}
	config, err := configLoader.GetProfileConfig("testincludeprofile2")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	if config.Region != "us-east-1" {
		t.Fatalf("Expected region %q, got %q", "us-east-1", config.Region)
	}
}

func TestIncludeSsoSession(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	configLoader := &vault.ConfigLoader{File: configFile}
	config, err := configLoader.GetProfileConfig("with-sso-session")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	if config.Region != "moon-1" { // Test not the same as SSO region
		t.Fatalf("Expected region %q, got %q", "moon-1", config.Region)
	}

	ssoStartURL := "https://d-123456789.example.com/start"
	if config.SSOStartURL != ssoStartURL {
		t.Fatalf("Expected sso_start_url %q, got %q", ssoStartURL, config.Region)
	}

	if config.SSORegion != "moon-2" { // Test not the same as profile region
		t.Fatalf("Expected sso_region %q, got %q", "moon-2", config.Region)
	}
	// Not checking sso_registration_scopes as it seems to be unused by aws-cli.
}

func TestProfileIsEmpty(t *testing.T) {
	p := vault.ProfileSection{Name: "foo"}
	if !p.IsEmpty() {
		t.Errorf("Expected p to be empty")
	}
}

func TestIniWithHeaderSavesWithHeader(t *testing.T) {
	f := newConfigFile(t, defaultsOnlyConfigWithHeader)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Save()
	if err != nil {
		t.Fatal(err)
	}

	expected := defaultsOnlyConfigWithHeader

	b, _ := os.ReadFile(f)

	if !bytes.Equal(expected, b) {
		t.Fatalf("Expected:\n%q\nGot:\n%q", expected, b)
	}
}

func TestIniWithDEFAULTHeader(t *testing.T) {
	f := newConfigFile(t, []byte(`[DEFAULT]
region=us-east-1
[default]
region=us-west-2
`))
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	expected := []vault.ProfileSection{
		{Name: "default", Region: "us-west-2"},
	}
	actual := cfg.ProfileSections()

	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("ProfileSections() mismatch (-expected +actual):\n%s", diff)
	}
}

func TestLoadedProfileDoesntReferToItself(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile foo]
source_profile=foo
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	def, ok := configFile.ProfileSection("foo")
	if !ok {
		t.Fatalf("Couldn't load profile foo")
	}

	expectedSourceProfile := "foo"
	if def.SourceProfile != expectedSourceProfile {
		t.Fatalf("Expected '%s', got '%s'", expectedSourceProfile, def.SourceProfile)
	}

	configLoader := &vault.ConfigLoader{File: configFile}
	config, err := configLoader.GetProfileConfig("foo")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	expectedSourceProfileName := ""
	if config.SourceProfileName != expectedSourceProfileName {
		t.Fatalf("Expected '%s', got '%s'", expectedSourceProfileName, config.SourceProfileName)
	}
}

func TestSourceProfileCanReferToParent(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile root]

[profile foo]
include_profile=root
source_profile=root
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	def, ok := configFile.ProfileSection("foo")
	if !ok {
		t.Fatalf("Couldn't load profile foo")
	}

	expectedSourceProfile := "root"
	if def.SourceProfile != expectedSourceProfile {
		t.Fatalf("Expected '%s', got '%s'", expectedSourceProfile, def.SourceProfile)
	}

	configLoader := &vault.ConfigLoader{File: configFile}
	config, err := configLoader.GetProfileConfig("foo")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	expectedSourceProfileName := "root"
	if config.SourceProfileName != expectedSourceProfileName {
		t.Fatalf("Expected '%s', got '%s'", expectedSourceProfileName, config.SourceProfileName)
	}
}

func TestSetSessionTags(t *testing.T) {
	var testCases = []struct {
		stringValue string
		expected    map[string]string
		ok          bool
	}{
		{"tag1=value1", map[string]string{"tag1": "value1"}, true},
		{
			"tag2=value2,tag3=value3,tag4=value4",
			map[string]string{"tag2": "value2", "tag3": "value3", "tag4": "value4"},
			true,
		},
		{" tagA = valueA ,  tagB  =  valueB  ,  tagC   =   valueC  ",
			map[string]string{"tagA": "valueA", "tagB": "valueB", "tagC": "valueC"},
			true,
		},
		{"", nil, false},
		{"tag1=value1,", nil, false},
		{"tagA=valueA,tagB", nil, false},
		{"tagOne,tagTwo=valueTwo", nil, false},
		{"tagI=valueI,tagII,tagIII=valueIII", nil, false},
	}

	for _, tc := range testCases {
		config := vault.ProfileConfig{}
		err := config.SetSessionTags(tc.stringValue)
		if tc.ok {
			if err != nil {
				t.Fatalf("Unsexpected parsing error: %s", err)
			}
			if !reflect.DeepEqual(tc.expected, config.SessionTags) {
				t.Fatalf("Expected SessionTags: %+v, got %+v", tc.expected, config.SessionTags)
			}
		} else {
			if err == nil {
				t.Fatalf("Expected an error parsing %#v, but got none", tc.stringValue)
			}
		}
	}
}

func TestSetTransitiveSessionTags(t *testing.T) {
	var testCases = []struct {
		stringValue string
		expected    []string
	}{
		{"tag1", []string{"tag1"}},
		{"tag2,tag3,tag4", []string{"tag2", "tag3", "tag4"}},
		{" tagA ,  tagB  ,   tagC   ", []string{"tagA", "tagB", "tagC"}},
		{"tag1,", []string{"tag1"}},
		{",tagA", []string{"tagA"}},
		{"", nil},
		{",", nil},
	}

	for _, tc := range testCases {
		config := vault.ProfileConfig{}
		config.SetTransitiveSessionTags(tc.stringValue)
		if !reflect.DeepEqual(tc.expected, config.TransitiveSessionTags) {
			t.Fatalf("Expected TransitiveSessionTags: %+v, got %+v", tc.expected, config.TransitiveSessionTags)
		}
	}
}

func TestSessionTaggingFromIni(t *testing.T) {
	os.Unsetenv("AWS_SESSION_TAGS")
	os.Unsetenv("AWS_TRANSITIVE_TAGS")
	f := newConfigFile(t, []byte(`
[profile tagged]
session_tags = tag1 = value1 , tag2=value2 ,tag3=value3
transitive_session_tags = tagOne ,tagTwo,tagThree
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "tagged"}
	config, err := configLoader.GetProfileConfig("tagged")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	expectedSessionTags := map[string]string{
		"tag1": "value1",
		"tag2": "value2",
		"tag3": "value3",
	}
	if !reflect.DeepEqual(expectedSessionTags, config.SessionTags) {
		t.Fatalf("Expected session_tags: %+v, got %+v", expectedSessionTags, config.SessionTags)
	}

	expectedTransitiveSessionTags := []string{"tagOne", "tagTwo", "tagThree"}
	if !reflect.DeepEqual(expectedTransitiveSessionTags, config.TransitiveSessionTags) {
		t.Fatalf("Expected transitive_session_tags: %+v, got %+v", expectedTransitiveSessionTags, config.TransitiveSessionTags)
	}
}

func TestSessionTaggingFromEnvironment(t *testing.T) {
	os.Setenv("AWS_SESSION_TAGS", " tagA = val1 , tagB=val2 ,tagC=val3")
	os.Setenv("AWS_TRANSITIVE_TAGS", " tagD ,tagE")
	defer os.Unsetenv("AWS_SESSION_TAGS")
	defer os.Unsetenv("AWS_TRANSITIVE_TAGS")

	f := newConfigFile(t, []byte(`
[profile tagged]
session_tags = tag1 = value1 , tag2=value2 ,tag3=value3
transitive_session_tags = tagOne ,tagTwo,tagThree
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "tagged"}
	config, err := configLoader.GetProfileConfig("tagged")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	expectedSessionTags := map[string]string{
		"tagA": "val1",
		"tagB": "val2",
		"tagC": "val3",
	}
	if !reflect.DeepEqual(expectedSessionTags, config.SessionTags) {
		t.Fatalf("Expected session_tags: %+v, got %+v", expectedSessionTags, config.SessionTags)
	}

	expectedTransitiveSessionTags := []string{"tagD", "tagE"}
	if !reflect.DeepEqual(expectedTransitiveSessionTags, config.TransitiveSessionTags) {
		t.Fatalf("Expected transitive_session_tags: %+v, got %+v", expectedTransitiveSessionTags, config.TransitiveSessionTags)
	}
}

func TestSessionTaggingFromEnvironmentChainedRoles(t *testing.T) {
	os.Setenv("AWS_SESSION_TAGS", "tagI=valI")
	os.Setenv("AWS_TRANSITIVE_TAGS", " tagII")
	defer os.Unsetenv("AWS_SESSION_TAGS")
	defer os.Unsetenv("AWS_TRANSITIVE_TAGS")

	f := newConfigFile(t, []byte(`
[profile base]

[profile interim]
session_tags=tag1=value1
transitive_session_tags=tag2
source_profile = base

[profile target]
session_tags=tagA=valueA
transitive_session_tags=tagB
source_profile = interim
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "target"}
	config, err := configLoader.GetProfileConfig("target")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	// Testing target profile, should have values populated from environment variables
	expectedSessionTags := map[string]string{"tagI": "valI"}
	if !reflect.DeepEqual(expectedSessionTags, config.SessionTags) {
		t.Fatalf("Expected session_tags: %+v, got %+v", expectedSessionTags, config.SessionTags)
	}

	expectedTransitiveSessionTags := []string{"tagII"}
	if !reflect.DeepEqual(expectedTransitiveSessionTags, config.TransitiveSessionTags) {
		t.Fatalf("Expected transitive_session_tags: %+v, got %+v", expectedTransitiveSessionTags, config.TransitiveSessionTags)
	}

	// Testing interim profile, parameters should come from the config, not environment
	interimConfig := config.SourceProfile
	expectedSessionTags = map[string]string{"tag1": "value1"}
	if !reflect.DeepEqual(expectedSessionTags, interimConfig.SessionTags) {
		t.Fatalf("Expected session_tags: %+v, got %+v", expectedSessionTags, interimConfig.SessionTags)
	}

	expectedTransitiveSessionTags = []string{"tag2"}
	if !reflect.DeepEqual(expectedTransitiveSessionTags, interimConfig.TransitiveSessionTags) {
		t.Fatalf("Expected transitive_session_tags: %+v, got %+v", expectedTransitiveSessionTags, interimConfig.TransitiveSessionTags)
	}

	// Testing base profile, should have empty parameters
	baseConfig := interimConfig.SourceProfile
	if len(baseConfig.SessionTags) > 0 {
		t.Fatalf("Expected session_tags to be empty, got %+v", baseConfig.SessionTags)
	}

	if len(baseConfig.TransitiveSessionTags) > 0 {
		t.Fatalf("Expected transitive_session_tags to be empty, got %+v", baseConfig.TransitiveSessionTags)
	}
}

// ---------------------------------------------------------------------------
// Parser correctness tests
//
// These document the exact behaviour of the ini.v1-based parser for AWS
// config file inputs.  They serve as a regression baseline so that any future
// parser swap can compare results directly.
// ---------------------------------------------------------------------------

// TestParserInlineHashComment verifies that a " #" sequence strips the rest of
// a value as a comment, matching the SpaceBeforeInlineComment option.
func TestParserInlineHashComment(t *testing.T) {
	cases := []struct{ input, want string }{
		{"region = us-east-1 # prod", "us-east-1"},
		{"region = us-east-1  # extra space", "us-east-1"},
		{"region = us-east-1 #no-space-after", "us-east-1"},
		{"region = us-east-1 #", "us-east-1"},
	}
	for _, tc := range cases {
		f := newConfigFile(t, []byte("[profile p]\n"+tc.input+"\n"))
		defer os.Remove(f)
		cfg, err := vault.LoadConfig(f)
		if err != nil {
			t.Fatalf("%q: load error: %v", tc.input, err)
		}
		p, _ := cfg.ProfileSection("p")
		if p.Region != tc.want {
			t.Errorf("%q: want %q, got %q", tc.input, tc.want, p.Region)
		}
	}
}

// TestParserInlineSemicolonComment verifies that " ;" strips a trailing
// semicolon comment, matching SpaceBeforeInlineComment behaviour.
func TestParserInlineSemicolonComment(t *testing.T) {
	cases := []struct{ input, want string }{
		{"region = us-east-1 ; prod region", "us-east-1"},
		{"region = us-east-1 ;", "us-east-1"},
	}
	for _, tc := range cases {
		f := newConfigFile(t, []byte("[profile p]\n"+tc.input+"\n"))
		defer os.Remove(f)
		cfg, err := vault.LoadConfig(f)
		if err != nil {
			t.Fatalf("%q: load error: %v", tc.input, err)
		}
		p, _ := cfg.ProfileSection("p")
		if p.Region != tc.want {
			t.Errorf("%q: want %q, got %q", tc.input, tc.want, p.Region)
		}
	}
}

// TestParserHashWithoutSpacePreserved verifies that "#" not preceded by a
// space is kept as part of the value — important for URLs and ARNs.
func TestParserHashWithoutSpacePreserved(t *testing.T) {
	cases := []struct{ input, want string }{
		{"endpoint_url = https://example.com/path#anchor", "https://example.com/path#anchor"},
		{"endpoint_url = https://example.com#", "https://example.com#"},
		{"role_session_name = foo#bar", "foo#bar"},
	}
	for _, tc := range cases {
		f := newConfigFile(t, []byte("[profile p]\n"+tc.input+"\n"))
		defer os.Remove(f)
		cfg, err := vault.LoadConfig(f)
		if err != nil {
			t.Fatalf("%q: load error: %v", tc.input, err)
		}
		p, _ := cfg.ProfileSection("p")
		got := p.EndpointURL + p.RoleSessionName // one of the two will be populated
		if got != tc.want {
			t.Errorf("%q: want %q, got %q", tc.input, tc.want, got)
		}
	}
}

// TestParserSemicolonWithoutSpacePreserved verifies that ";" not preceded by a
// space stays in the value.
func TestParserSemicolonWithoutSpacePreserved(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
role_session_name = foo;bar
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.ProfileSection("p")
	if p.RoleSessionName != "foo;bar" {
		t.Errorf("want %q, got %q", "foo;bar", p.RoleSessionName)
	}
}

// TestParserSectionHeaderWithComment verifies that a comment after the closing
// "]" of a section header does not prevent the section from being recognised.
func TestParserSectionHeaderWithComment(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p] # production account
region = us-east-1
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.ProfileSection("p")
	if !ok {
		t.Fatal("expected profile 'p' to be parsed despite comment on section header")
	}
	if p.Region != "us-east-1" {
		t.Errorf("want %q, got %q", "us-east-1", p.Region)
	}
}

// TestParserEmptyValue verifies that "key =" (empty value) is stored as an
// empty string rather than omitted.
func TestParserEmptyValue(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
role_arn =
region = us-east-1
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.ProfileSection("p")
	if !ok {
		t.Fatal("profile not found")
	}
	if p.RoleARN != "" {
		t.Errorf("want empty role_arn, got %q", p.RoleARN)
	}
	if p.Region != "us-east-1" {
		t.Errorf("want %q, got %q", "us-east-1", p.Region)
	}
}

// TestParserMixedCaseKeys verifies that key names are normalised to lower-case
// regardless of how they appear in the file (InsensitiveKeys: true).
func TestParserMixedCaseKeys(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
REGION = us-east-1
Role_Arn = arn:aws:iam::123:role/Admin
MFA_Serial = arn:aws:iam::123:mfa/user
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.ProfileSection("p")
	if p.Region != "us-east-1" {
		t.Errorf("REGION: want %q, got %q", "us-east-1", p.Region)
	}
	if p.RoleARN != "arn:aws:iam::123:role/Admin" {
		t.Errorf("Role_Arn: want arn, got %q", p.RoleARN)
	}
	if p.MfaSerial != "arn:aws:iam::123:mfa/user" {
		t.Errorf("MFA_Serial: want arn, got %q", p.MfaSerial)
	}
}

// TestParserWhitespaceTrimmedAroundValue verifies that leading and trailing
// spaces around a value are stripped.
func TestParserWhitespaceTrimmedAroundValue(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
region   =   ap-southeast-1
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.ProfileSection("p")
	if p.Region != "ap-southeast-1" {
		t.Errorf("want %q, got %q", "ap-southeast-1", p.Region)
	}
}

// TestParserValueContainingEquals verifies that only the first "=" is the
// key-value delimiter — subsequent "=" are part of the value.
func TestParserValueContainingEquals(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
credential_process = aws-vault export --format=json --no-session
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.ProfileSection("p")
	want := "aws-vault export --format=json --no-session"
	if p.CredentialProcess != want {
		t.Errorf("want %q, got %q", want, p.CredentialProcess)
	}
}

// TestParserARNValue verifies that ARN strings (which contain ":" separators)
// are preserved verbatim.  ini.v1 uses "=:" as key-value delimiters, so the
// first "=" stops key scanning before any ":" in the value is reached.
func TestParserARNValue(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
role_arn = arn:aws:iam::123456789012:role/MyRole
mfa_serial = arn:aws:iam::123456789012:mfa/myuser
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.ProfileSection("p")
	wantARN := "arn:aws:iam::123456789012:role/MyRole"
	if p.RoleARN != wantARN {
		t.Errorf("role_arn: want %q, got %q", wantARN, p.RoleARN)
	}
	wantMFA := "arn:aws:iam::123456789012:mfa/myuser"
	if p.MfaSerial != wantMFA {
		t.Errorf("mfa_serial: want %q, got %q", wantMFA, p.MfaSerial)
	}
}

// TestParserLargeNumberPreserved verifies that very large numeric strings are
// kept as-is and not truncated or converted.
func TestParserLargeNumberPreserved(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
role_session_name = 1234567890123456789012345678901234567890
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.ProfileSection("p")
	want := "1234567890123456789012345678901234567890"
	if p.RoleSessionName != want {
		t.Errorf("want %q, got %q", want, p.RoleSessionName)
	}
}

// TestParserNestedValuesSkippedForProfileFields verifies that indented
// sub-property lines (AllowNestedValues) do not surface as profile fields —
// aws-vault does not read s3, http_proxy, or other nested sections.
func TestParserNestedValuesSkippedForProfileFields(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
region = us-west-2
s3 =
  max_concurrent_requests = 10
  max_queue_size = 1000
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.ProfileSection("p")
	if !ok {
		t.Fatal("profile not found")
	}
	if p.Region != "us-west-2" {
		t.Errorf("want %q, got %q", "us-west-2", p.Region)
	}
}

// TestParserPreSectionKeysIgnored verifies that key=value lines appearing
// before any section header are silently discarded.
func TestParserPreSectionKeysIgnored(t *testing.T) {
	f := newConfigFile(t, []byte(`region = us-east-1
[profile p]
region = eu-west-1
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.ProfileSection("p")
	if p.Region != "eu-west-1" {
		t.Errorf("want %q, got %q", "eu-west-1", p.Region)
	}
}

// TestParserDuplicateSectionsMerged verifies that when the same section name
// appears more than once its keys are merged, and ProfileSections() lists it
// only once.
func TestParserDuplicateSectionsMerged(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
region = us-east-1

[profile p]
role_arn = arn:aws:iam::123:role/Admin
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.ProfileSection("p")
	if !ok {
		t.Fatal("profile not found")
	}
	if p.Region != "us-east-1" {
		t.Errorf("region: want %q, got %q", "us-east-1", p.Region)
	}
	if p.RoleARN != "arn:aws:iam::123:role/Admin" {
		t.Errorf("role_arn: want arn, got %q", p.RoleARN)
	}
	count := 0
	for _, s := range cfg.ProfileSections() {
		if s.Name == "p" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("want profile 'p' once in ProfileSections(), got %d", count)
	}
}

// TestParserDuplicateKeyLastValueWins verifies that when a key appears more
// than once in the same section, the last value is used.
func TestParserDuplicateKeyLastValueWins(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
region = us-east-1
region = eu-west-1
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.ProfileSection("p")
	if p.Region != "eu-west-1" {
		t.Errorf("want last value %q, got %q", "eu-west-1", p.Region)
	}
}

// TestParserDeclarationOrderPreserved verifies that ProfileSections() returns
// profiles in the order they appear in the file.
func TestParserDeclarationOrderPreserved(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile alpha]
region = us-east-1
[profile beta]
region = us-west-2
[profile gamma]
region = eu-west-1
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	sections := cfg.ProfileSections()
	names := make([]string, len(sections))
	for i, s := range sections {
		names[i] = s.Name
	}
	want := []string{"alpha", "beta", "gamma"}
	if !reflect.DeepEqual(want, names) {
		t.Errorf("want order %v, got %v", want, names)
	}
}

// TestParserAllSectionTypes verifies that [default], [profile name] and
// [sso-session name] are all correctly identified and accessible.
func TestParserAllSectionTypes(t *testing.T) {
	f := newConfigFile(t, []byte(`[default]
region = us-east-1

[profile myprofile]
role_arn = arn:aws:iam::123:role/Admin
sso_session = myorg

[sso-session myorg]
sso_start_url = https://myorg.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	def, ok := cfg.ProfileSection("default")
	if !ok || def.Region != "us-east-1" {
		t.Errorf("default: want region us-east-1, got %q (ok=%v)", def.Region, ok)
	}

	prof, ok := cfg.ProfileSection("myprofile")
	if !ok || prof.SSOSession != "myorg" {
		t.Errorf("myprofile: want sso_session myorg, got %q (ok=%v)", prof.SSOSession, ok)
	}

	sso, ok := cfg.SSOSessionSection("myorg")
	if !ok || sso.SSOStartURL != "https://myorg.awsapps.com/start" {
		t.Errorf("sso-session: want start url, got %q (ok=%v)", sso.SSOStartURL, ok)
	}
	if sso.SSORegistrationScopes != "sso:account:access" {
		t.Errorf("sso-session: want registration scopes, got %q", sso.SSORegistrationScopes)
	}
}

// TestParserCommentOnlyLines verifies that lines starting with "#" or ";" are
// treated as comments regardless of surrounding content.
func TestParserCommentOnlyLines(t *testing.T) {
	f := newConfigFile(t, []byte(`# full-line hash comment
[profile p]
; full-line semicolon comment
region = us-east-1
# trailing comment
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.ProfileSection("p")
	if !ok {
		t.Fatal("profile not found")
	}
	if p.Region != "us-east-1" {
		t.Errorf("want %q, got %q", "us-east-1", p.Region)
	}
}

// TestParserQuotedValueStripped verifies ini.v1's default behaviour of
// stripping matching surrounding double-quotes from a value.
// Note: the AWS SDK parser does NOT strip quotes — this is an ini.v1-specific
// behaviour that a replacement parser must handle explicitly or document.
func TestParserQuotedValueStripped(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
region = "us-east-1"
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.ProfileSection("p")
	// ini.v1 strips surrounding double-quotes by default.
	if p.Region != "us-east-1" {
		t.Errorf("want %q (quotes stripped), got %q", "us-east-1", p.Region)
	}
}

// TestParserTabBeforeCommentNotStripped documents that ini.v1 with
// SpaceBeforeInlineComment=true requires a literal space (" #" or " ;") to
// trigger comment stripping.  A tab before "#" or ";" is NOT a space, so the
// tab and everything after it remains in the value.
// The AWS SDK treats any whitespace (space OR tab) before a comment character
// as a valid separator — this is an important divergence for hand-edited files.
func TestParserTabBeforeCommentNotStripped(t *testing.T) {
	cases := []struct{ input, want string }{
		{"region = us-east-1\t# comment", "us-east-1\t# comment"},
		{"region = us-east-1\t\t# comment", "us-east-1\t\t# comment"},
		{"region = us-east-1\t; comment", "us-east-1\t; comment"},
	}
	for _, tc := range cases {
		f := newConfigFile(t, []byte("[profile p]\n"+tc.input+"\n"))
		defer os.Remove(f)
		cfg, err := vault.LoadConfig(f)
		if err != nil {
			t.Fatalf("%q: load error: %v", tc.input, err)
		}
		p, _ := cfg.ProfileSection("p")
		if p.Region != tc.want {
			t.Errorf("%q: want %q, got %q", tc.input, tc.want, p.Region)
		}
	}
}

// TestParserSpacesInsideSectionBracketsNotTrimmed documents that ini.v1 does
// NOT trim whitespace inside the "[" "]" delimiters of a section header.
// "[ profile foo ]" is stored with section name " profile foo " (spaces
// preserved), so ProfileSection("foo") — which looks up "profile foo" — returns
// false.  The AWS SDK DOES trim this whitespace, making the lookup succeed.
func TestParserSpacesInsideSectionBracketsNotTrimmed(t *testing.T) {
	f := newConfigFile(t, []byte("[ profile foo ]\nregion = us-east-1\n"))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	_, ok := cfg.ProfileSection("foo")
	if ok {
		t.Error("ini.v1 preserves spaces inside brackets, so lookup for 'foo' should fail")
	}
}

// TestParserValueStartingWithHashPreserved documents the boundary condition
// where a value begins with "#" or ";" after the "=" without a preceding
// space.  ini.v1 with SpaceBeforeInlineComment=true searches for " #" / " ;",
// so a hash or semicolon as the first character of the value is NOT treated as
// a comment — it stays in the value.
// Contrast with the AWS SDK, which returns "" for "i = # comment".
func TestParserValueStartingWithHashPreserved(t *testing.T) {
	cases := []struct {
		key, input, want string
	}{
		{"region", "region = # a note", "# a note"},
		{"region", "region = ; a note", "; a note"},
	}
	for _, tc := range cases {
		f := newConfigFile(t, []byte("[profile p]\n"+tc.input+"\n"))
		defer os.Remove(f)
		cfg, err := vault.LoadConfig(f)
		if err != nil {
			t.Fatalf("%q: load error: %v", tc.input, err)
		}
		p, _ := cfg.ProfileSection("p")
		if p.Region != tc.want {
			t.Errorf("%q: want %q, got %q", tc.input, tc.want, p.Region)
		}
	}
}

// TestParserColonKeyValueDelimiter documents that ini.v1 accepts ":" as a
// key-value separator in addition to "=" (KeyValueDelimiters = "=:").
// A line like "region: us-east-1" is parsed identically to "region = us-east-1".
// Any replacement parser that only handles "=" would silently discard such
// lines.  In practice AWS configs use "=" exclusively, but the contract should
// be explicit.
func TestParserColonKeyValueDelimiter(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
region: us-east-1
role_arn: arn:aws:iam::123456789012:role/MyRole
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.ProfileSection("p")
	if !ok {
		t.Fatal("profile not found")
	}
	if p.Region != "us-east-1" {
		t.Errorf("region: want %q, got %q", "us-east-1", p.Region)
	}
	// role_arn: arn:aws:... — the first ":" splits key from value, leaving
	// " arn:aws:iam::..." as the value (colons in ARNs are safe because they
	// come AFTER the key delimiter).
	wantARN := "arn:aws:iam::123456789012:role/MyRole"
	if p.RoleARN != wantARN {
		t.Errorf("role_arn: want %q, got %q", wantARN, p.RoleARN)
	}
}

// TestParserSingleQuotedValueStripped verifies that ini.v1 strips matching
// surrounding single-quotes as well as double-quotes.
// Note: the AWS SDK preserves quotes — this is an ini.v1-specific behaviour.
func TestParserSingleQuotedValueStripped(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
region = 'us-east-1'
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.ProfileSection("p")
	if p.Region != "us-east-1" {
		t.Errorf("want %q (single quotes stripped), got %q", "us-east-1", p.Region)
	}
}

// TestParserEmptyFile verifies that LoadConfig on a zero-byte file succeeds and
// returns no profile sections.
func TestParserEmptyFile(t *testing.T) {
	f := newConfigFile(t, []byte{})
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatalf("unexpected error on empty file: %v", err)
	}
	if sections := cfg.ProfileSections(); len(sections) != 0 {
		t.Errorf("want 0 sections, got %d: %v", len(sections), sections)
	}
}

// TestParserFileWithoutTrailingNewline verifies that a config file whose last
// line is not terminated by a newline is parsed correctly.
func TestParserFileWithoutTrailingNewline(t *testing.T) {
	f := newConfigFile(t, []byte("[profile p]\nregion=us-east-1")) // no trailing \n
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p, ok := cfg.ProfileSection("p")
	if !ok {
		t.Fatal("profile not found")
	}
	if p.Region != "us-east-1" {
		t.Errorf("want %q, got %q", "us-east-1", p.Region)
	}
}

// TestParserServicesSectionNotInProfileSections verifies that [services name]
// sections (used by the AWS CLI for endpoint customisation) are not returned by
// ProfileSections().
func TestParserServicesSectionNotInProfileSections(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile myprofile]
region = us-east-1

[services my-endpoints]
s3 =
  endpoint_url = https://s3.example.com

[profile another]
region = us-west-2
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	sections := cfg.ProfileSections()
	for _, s := range sections {
		if strings.Contains(s.Name, "services") {
			t.Errorf("services section must not appear in ProfileSections(), got %q", s.Name)
		}
	}
	if len(sections) != 2 {
		t.Errorf("want 2 profile sections, got %d: %v", len(sections), sections)
	}
}

// TestParserSectionHeaderWithSemicolonComment extends
// TestParserSectionHeaderWithComment to verify that a semicolon comment after
// the closing "]" is also handled correctly.
func TestParserSectionHeaderWithSemicolonComment(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p] ; production account
region = us-east-1
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.ProfileSection("p")
	if !ok {
		t.Fatal("expected profile 'p' to be parsed despite semicolon comment on section header")
	}
	if p.Region != "us-east-1" {
		t.Errorf("want %q, got %q", "us-east-1", p.Region)
	}
}

// TestParserDurationSecondsEmpty verifies that an empty duration_seconds value
// ("duration_seconds =") does not cause a parse error and results in the zero
// uint value (treated as unset).
func TestParserDurationSecondsEmpty(t *testing.T) {
	f := newConfigFile(t, []byte(`[profile p]
duration_seconds =
region = us-east-1
`))
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	p, ok := cfg.ProfileSection("p")
	if !ok {
		t.Fatal("profile not found")
	}
	if p.DurationSeconds != 0 {
		t.Errorf("want DurationSeconds=0 for empty value, got %d", p.DurationSeconds)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func generateLargeConfig(b *testing.B, n int) string {
	b.Helper()
	f, err := os.CreateTemp("", "aws-config-large")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	fmt.Fprintf(f, "[default]\nregion=us-east-1\n\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(f, "[profile sso-acct%d-role%d]\nsso_account_id=%012d\nsso_role_name=role%d\nsso_start_url=https://d-abc123.awsapps.com/start\nsso_region=us-east-1\nregion=us-east-1\n\n", i, i, i, i)
		fmt.Fprintf(f, "[profile exec-sso-acct%d-role%d]\ncredential_process=aws-vault export --format=json sso-acct%d-role%d\n\n", i, i, i, i)
	}
	return f.Name()
}

func BenchmarkParseSmallConfig(b *testing.B) {
	f := newConfigFile(b, exampleConfig)
	defer os.Remove(f)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg, err := vault.LoadConfig(f)
		if err != nil {
			b.Fatal(err)
		}
		_ = cfg
	}
}

func BenchmarkParseLargeSyntheticConfig(b *testing.B) {
	path := generateLargeConfig(b, 87000)
	defer os.Remove(path)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg, err := vault.LoadConfig(path)
		if err != nil {
			b.Fatal(err)
		}
		_ = cfg
	}
}

func BenchmarkParseRealConfig(b *testing.B) {
	home, err := os.UserHomeDir()
	if err != nil {
		b.Skip("no home dir:", err)
	}
	path := home + "/.aws/config"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		b.Skip("no config file at", path)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg, err := vault.LoadConfig(path)
		if err != nil {
			b.Fatal(err)
		}
		_ = cfg
	}
}

func BenchmarkProfileSectionLookup(b *testing.B) {
	f := newConfigFile(b, exampleConfig)
	defer os.Remove(f)
	cfg, err := vault.LoadConfig(f)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, _ := cfg.ProfileSection("withMFA")
		_ = p
	}
}

func BenchmarkProfileSections(b *testing.B) {
	home, err := os.UserHomeDir()
	if err != nil {
		b.Skip("no home dir:", err)
	}
	path := home + "/.aws/config"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		b.Skip("no config file at", path)
	}
	cfg, err := vault.LoadConfig(path)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sections := cfg.ProfileSections()
		_ = sections
	}
}
