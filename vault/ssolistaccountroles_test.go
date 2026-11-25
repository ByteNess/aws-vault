package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
)

// rolesServer answers ListAccountRoles with one page per entry of pages,
// chained by next tokens, after one 401 if rejectFirst is set. It records the
// bearer token, account_id and next_token of every call.
type rolesServer struct {
	pages       []string
	rejectFirst bool
	tokens      []string
	accountIDs  []string
	nextTokens  []string
}

func (s *rolesServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.tokens = append(s.tokens, r.Header.Get("X-Amz-Sso_bearer_token"))
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path != "/assignment/roles" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if s.rejectFirst {
		s.rejectFirst = false
		w.Header().Set("X-Amzn-Errortype", "UnauthorizedException")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"__type":"UnauthorizedException","message":"refused"}`)
		return
	}

	next := r.URL.Query().Get("next_token")
	s.nextTokens = append(s.nextTokens, next)
	s.accountIDs = append(s.accountIDs, r.URL.Query().Get("account_id"))
	page := 0
	if next != "" {
		_, _ = fmt.Sscanf(next, "page-%d", &page)
	}
	body := `{"roleList":[` + s.pages[page] + `]`
	if page+1 < len(s.pages) {
		body += fmt.Sprintf(`,"nextToken":"page-%d"`, page+1)
	}
	_, _ = fmt.Fprint(w, body+"}")
}

func newRolesTestProvider(t *testing.T, s *rolesServer) *SSORoleCredentialsProvider {
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
	return p
}

func TestListAccountRoles_ReturnsEveryPageForTheAccount(t *testing.T) {
	s := &rolesServer{pages: []string{
		`{"accountId":"111111111111","roleName":"Administrator"},{"accountId":"111111111111","roleName":"ReadOnly"}`,
		`{"accountId":"111111111111","roleName":"Billing"}`,
	}}
	p := newRolesTestProvider(t, s)

	roles, err := p.ListAccountRoles(context.Background(), "111111111111")
	if err != nil {
		t.Fatal(err)
	}
	want := []SSOAccountRole{
		{AccountID: "111111111111", RoleName: "Administrator"},
		{AccountID: "111111111111", RoleName: "ReadOnly"},
		{AccountID: "111111111111", RoleName: "Billing"},
	}
	if !reflect.DeepEqual(roles, want) {
		t.Errorf("roles = %+v, want %+v", roles, want)
	}
	if !reflect.DeepEqual(s.accountIDs, []string{"111111111111", "111111111111"}) {
		t.Errorf("account IDs sent = %q", s.accountIDs)
	}
	if !reflect.DeepEqual(s.nextTokens, []string{"", "page-1"}) {
		t.Errorf("next tokens sent = %q", s.nextTokens)
	}
	if !reflect.DeepEqual(s.tokens, []string{"cached", "cached"}) {
		t.Errorf("bearer tokens sent = %q", s.tokens)
	}
}

func TestListAccountRoles_NoRoles(t *testing.T) {
	p := newRolesTestProvider(t, &rolesServer{pages: []string{``}})

	roles, err := p.ListAccountRoles(context.Background(), "111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 0 {
		t.Errorf("roles = %+v, want none", roles)
	}
}

func TestListAccountRoles_ReplacesRejectedCachedToken(t *testing.T) {
	s := &rolesServer{
		pages:       []string{`{"accountId":"111111111111","roleName":"Administrator"}`},
		rejectFirst: true,
	}
	p := newRolesTestProvider(t, s)

	roles, err := p.ListAccountRoles(context.Background(), "111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 {
		t.Errorf("roles = %+v, want one", roles)
	}
	if !reflect.DeepEqual(s.tokens, []string{"cached", "fresh"}) {
		t.Errorf("bearer tokens sent = %q, want the cached token then a fresh one", s.tokens)
	}
}
