package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
)

// accountsServer answers ListAccounts with one page per entry of pages,
// chained by next tokens. It answers with the statuses queued in failures
// first, and records the bearer token and next_token of every call.
type accountsServer struct {
	pages      []string
	failures   []int
	tokens     []string
	nextTokens []string
}

func (s *accountsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.tokens = append(s.tokens, r.Header.Get("X-Amz-Sso_bearer_token"))
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path != "/assignment/accounts" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(s.failures) > 0 {
		status := s.failures[0]
		s.failures = s.failures[1:]
		errType := "UnauthorizedException"
		if status == http.StatusTooManyRequests {
			errType = "TooManyRequestsException"
		}
		w.Header().Set("X-Amzn-Errortype", errType)
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"__type":%q,"message":"refused"}`, errType)
		return
	}

	next := r.URL.Query().Get("next_token")
	s.nextTokens = append(s.nextTokens, next)
	page := 0
	if next != "" {
		_, _ = fmt.Sscanf(next, "page-%d", &page)
	}
	body := `{"accountList":[` + s.pages[page] + `]`
	if page+1 < len(s.pages) {
		body += fmt.Sprintf(`,"nextToken":"page-%d"`, page+1)
	}
	_, _ = fmt.Fprint(w, body+"}")
}

func newAccountsTestProvider(t *testing.T, s *accountsServer) *SSORoleCredentialsProvider {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	p := newTestSSORoleProvider()
	p.SSOClient = sso.New(sso.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		RetryMaxAttempts: 1,
	})
	p.OIDCTokenCache = &testTokenCache{token: testToken("cached")}
	p.newOIDCTokenFn = func(context.Context) (*OIDCTokenData, error) {
		return testToken("fresh"), nil
	}
	p.ssoSleep = func(context.Context, time.Duration) error { return nil }
	return p
}

func TestListAccounts_ReturnsEveryPage(t *testing.T) {
	s := &accountsServer{pages: []string{
		`{"accountId":"111111111111","accountName":"dev","emailAddress":"dev@example.com"},{"accountId":"222222222222","accountName":"prod","emailAddress":"prod@example.com"}`,
		`{"accountId":"333333333333","accountName":"audit","emailAddress":"audit@example.com"}`,
	}}
	p := newAccountsTestProvider(t, s)

	accounts, err := p.ListAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []SSOAccount{
		{AccountID: "111111111111", AccountName: "dev", EmailAddress: "dev@example.com"},
		{AccountID: "222222222222", AccountName: "prod", EmailAddress: "prod@example.com"},
		{AccountID: "333333333333", AccountName: "audit", EmailAddress: "audit@example.com"},
	}
	if !reflect.DeepEqual(accounts, want) {
		t.Errorf("accounts = %+v, want %+v", accounts, want)
	}
	if !reflect.DeepEqual(s.nextTokens, []string{"", "page-1"}) {
		t.Errorf("next tokens sent = %q", s.nextTokens)
	}
	if !reflect.DeepEqual(s.tokens, []string{"cached", "cached"}) {
		t.Errorf("bearer tokens sent = %q", s.tokens)
	}
}

func TestListAccounts_NoAccounts(t *testing.T) {
	p := newAccountsTestProvider(t, &accountsServer{pages: []string{``}})

	accounts, err := p.ListAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 0 {
		t.Errorf("accounts = %+v, want none", accounts)
	}
}

func TestListAccounts_ReplacesRejectedCachedToken(t *testing.T) {
	s := &accountsServer{
		pages:    []string{`{"accountId":"111111111111","accountName":"dev","emailAddress":"dev@example.com"}`},
		failures: []int{http.StatusUnauthorized},
	}
	p := newAccountsTestProvider(t, s)

	accounts, err := p.ListAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Errorf("accounts = %+v, want one", accounts)
	}
	if !reflect.DeepEqual(s.tokens, []string{"cached", "fresh"}) {
		t.Errorf("bearer tokens sent = %q, want the cached token then a fresh one", s.tokens)
	}
}

func TestListAccounts_RetriesRateLimitWhenParallelSafe(t *testing.T) {
	s := &accountsServer{
		pages:    []string{`{"accountId":"111111111111","accountName":"dev","emailAddress":"dev@example.com"}`},
		failures: []int{http.StatusTooManyRequests},
	}
	p := newAccountsTestProvider(t, s)
	p.RetryRateLimit = true

	accounts, err := p.ListAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || len(s.tokens) != 2 {
		t.Errorf("got %d accounts after %d calls, want 1 after 2", len(accounts), len(s.tokens))
	}
}

func TestListAccounts_FailsOnRateLimitWithoutParallelSafe(t *testing.T) {
	s := &accountsServer{pages: []string{``}, failures: []int{http.StatusTooManyRequests}}
	p := newAccountsTestProvider(t, s)

	if _, err := p.ListAccounts(context.Background()); !isSSORateLimitError(err) {
		t.Errorf("err = %v, want the rate limit error", err)
	}
}
