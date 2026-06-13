// Package-level benchmarks that compare the iniv1 and custom parser backends
// side-by-side on the same inputs.  Run with:
//
//	go test -bench=. -benchmem -count=6 ./vault/configparser/ | tee /tmp/bench.txt
package configparser_test

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteness/aws-vault/v7/vault/configparser/custom"
	"github.com/byteness/aws-vault/v7/vault/configparser/iniv1"
)

// TestMain discards log output from the parser backends so benchmark output
// is not swamped by "Unrecognised ini file section" messages from iniv1.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// smallConfig is a representative config with several profiles.
const smallConfig = `[default]
region=us-east-1

[profile dev]
region=us-west-2
mfa_serial=arn:aws:iam::123456789012:mfa/user

[profile prod]
source_profile=dev
role_arn=arn:aws:iam::999999999999:role/DeployRole
duration_seconds=3600

[profile sso-user]
sso_session=my-sso
sso_account_id=111122223333
sso_role_name=ReadOnly

[sso-session my-sso]
sso_start_url=https://d-abc123.awsapps.com/start
sso_region=us-east-1
sso_registration_scopes=sso:account:access
`

func generateLargeConfig(tb testing.TB, n int) string {
	tb.Helper()
	f, err := os.CreateTemp("", "aws-config-bench")
	if err != nil {
		tb.Fatal(err)
	}
	fmt.Fprintf(f, "[default]\nregion=us-east-1\n\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(f, "[profile sso-acct%d]\nsso_account_id=%012d\nsso_role_name=role%d\nsso_start_url=https://d-abc123.awsapps.com/start\nsso_region=us-east-1\nregion=us-east-1\n\n", i, i, i)
		fmt.Fprintf(f, "[profile exec-acct%d]\ncredential_process=aws-vault export --format=json sso-acct%d\n\n", i, i)
	}
	name := f.Name()
	f.Close()
	tb.Cleanup(func() { os.Remove(name) })
	return name
}

func writeSmallConfig(tb testing.TB) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "config")
	if err := os.WriteFile(path, []byte(smallConfig), 0600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// ── Small config ──────────────────────────────────────────────────────────────

func BenchmarkIniv1ParseSmall(b *testing.B) {
	path := writeSmallConfig(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := iniv1.New()
		if err := p.Load(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCustomParseSmall(b *testing.B) {
	path := writeSmallConfig(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := custom.New()
		if err := p.Load(path); err != nil {
			b.Fatal(err)
		}
	}
}

// ── Large synthetic config (87 k profiles) ───────────────────────────────────

func BenchmarkIniv1ParseLarge(b *testing.B) {
	path := generateLargeConfig(b, 100000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := iniv1.New()
		if err := p.Load(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCustomParseLarge(b *testing.B) {
	path := generateLargeConfig(b, 100000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := custom.New()
		if err := p.Load(path); err != nil {
			b.Fatal(err)
		}
	}
}

// ── Profile lookup (post-load) ────────────────────────────────────────────────

func BenchmarkIniv1ProfileSectionLookup(b *testing.B) {
	path := writeSmallConfig(b)
	p := iniv1.New()
	if err := p.Load(path); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prof, _ := p.ProfileSection("prod")
		_ = prof
	}
}

func BenchmarkCustomProfileSectionLookup(b *testing.B) {
	path := writeSmallConfig(b)
	p := custom.New()
	if err := p.Load(path); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prof, _ := p.ProfileSection("prod")
		_ = prof
	}
}

// ── ProfileSections() list traversal ─────────────────────────────────────────

func BenchmarkIniv1ProfileSections(b *testing.B) {
	path := writeSmallConfig(b)
	p := iniv1.New()
	if err := p.Load(path); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sections := p.ProfileSections()
		_ = sections
	}
}

func BenchmarkCustomProfileSections(b *testing.B) {
	path := writeSmallConfig(b)
	p := custom.New()
	if err := p.Load(path); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sections := p.ProfileSections()
		_ = sections
	}
}
