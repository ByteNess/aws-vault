package cli

import (
	"io"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

const completionTestConfig = `[sso-session my-sso]
sso_start_url=https://sso.example/start
sso_region=eu-west-1

[sso-session other-sso]
sso_start_url=https://other.example/start
sso_region=eu-west-1

[profile dev]
sso_session=my-sso

[profile prod]
region=eu-west-1
`

// completions returns what `aws-vault --completion-bash <words>` prints: the
// candidates the bash, zsh and fish completion scripts all offer for a command
// line. The last word is the one being completed, "" for a new word.
func completions(t *testing.T, words ...string) []string {
	t.Helper()
	configFile, removeConfig := exampleConfigFile(completionTestConfig)
	t.Cleanup(removeConfig)
	t.Setenv("AWS_CONFIG_FILE", configFile)

	app := kingpin.New("aws-vault", "")
	app.Terminate(nil)
	ConfigureCommands(app, ConfigureGlobals(app), "test")

	// kingpin prints completions straight to os.Stdout
	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	_, parseErr := app.Parse(append([]string{"--completion-bash"}, words...))
	os.Stdout = stdout
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if parseErr != nil {
		t.Logf("parse error (expected for a partial command line): %v", parseErr)
	}

	got := strings.Fields(string(out))
	sort.Strings(got)
	return got
}

// containsAll reports whether list holds every one of want.
func containsAll(list []string, want ...string) bool {
	for _, w := range want {
		if !slices.Contains(list, w) {
			return false
		}
	}
	return true
}

func TestCompletion_Commands(t *testing.T) {
	got := completions(t, "")
	want := []string{"add", "clear", "exec", "export", "help", "list", "login", "migrate-backend", "remove", "rotate", "sso", "version"}
	if !containsAll(got, want...) {
		t.Errorf("commands = %q, want them to include %q", got, want)
	}
}

func TestCompletion_SSOSubcommands(t *testing.T) {
	got := completions(t, "sso", "")
	want := []string{"export", "list-account-roles", "list-accounts"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sso subcommands = %q, want %q", got, want)
	}
}

// Every command that takes a profile must offer the profile names. A command
// that drops its hint silently loses completion in all three shells.
func TestCompletion_Profiles(t *testing.T) {
	want := []string{"dev", "prod"}
	for _, command := range [][]string{
		{"exec"},
		{"export"},
		{"login"},
		{"clear"},
		{"remove"},
		{"rotate"},
		{"sso", "export"},
		{"sso", "list-accounts"},
		{"sso", "list-account-roles"},
	} {
		got := completions(t, append(command, "")...)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: profiles = %q, want %q", strings.Join(command, " "), got, want)
		}
	}
}

func TestCompletion_SSOSessionNames(t *testing.T) {
	want := []string{"my-sso", "other-sso"}
	for _, subcommand := range []string{"export", "list-accounts", "list-account-roles"} {
		got := completions(t, "sso", subcommand, "--sso-session", "")
		if !reflect.DeepEqual(got, want) {
			t.Errorf("sso %s --sso-session: got %q, want %q", subcommand, got, want)
		}
	}
}

func TestCompletion_Flags(t *testing.T) {
	for _, tc := range []struct {
		words []string
		want  []string
	}{
		{[]string{"exec", "--"}, []string{"--no-session", "--duration", "--stdout", "--device-code", "--browser", "--backend"}},
		{[]string{"export", "--"}, []string{"--format", "--no-session", "--stdout"}},
		{[]string{"sso", "export", "--"}, []string{"--format", "--sso-session", "--stdout", "--device-code", "--browser"}},
		{[]string{"sso", "list-accounts", "--"}, []string{"--format", "--sso-session"}},
		{[]string{"sso", "list-account-roles", "--"}, []string{"--account-id", "--format", "--sso-session"}},
	} {
		got := completions(t, tc.words...)
		if !containsAll(got, tc.want...) {
			t.Errorf("%s: flags = %q, want them to include %q", strings.Join(tc.words, " "), got, tc.want)
		}
	}
}
