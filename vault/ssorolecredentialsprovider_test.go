package vault

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newTestCallbackServer builds an oauthCallbackServer with a known state and a
// buffered result channel, without starting the underlying HTTP listener. The
// listener is only needed for redirectURI(); tests that don't call it may leave
// it nil.
func newTestCallbackServer(t *testing.T) *oauthCallbackServer {
	t.Helper()
	s, err := newOauthCallbackServer()
	if err != nil {
		t.Fatalf("newOauthCallbackServer: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })
	return s
}

func TestNewOauthCallbackServer_BindsLoopback(t *testing.T) {
	s := newTestCallbackServer(t)

	tcpAddr, ok := s.ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr is not *net.TCPAddr: %T", s.ln.Addr())
	}
	if !tcpAddr.IP.IsLoopback() {
		t.Errorf("listener not bound to loopback: %s", tcpAddr.IP)
	}

	if cap(s.resultChan) != 1 {
		t.Errorf("resultChan cap = %d, want 1 (buffered so handler never blocks)", cap(s.resultChan))
	}
	if s.state == "" {
		t.Error("expected non-empty CSRF state")
	}
}

func TestRedirectURI(t *testing.T) {
	s := newTestCallbackServer(t)

	got := s.redirectURI()
	port := s.ln.Addr().(*net.TCPAddr).Port
	want := "http://127.0.0.1:" + strconv.Itoa(port) + "/oauth/callback"
	if got != want {
		t.Errorf("redirectURI() = %q, want %q", got, want)
	}
}

func TestHandleCallback_Success(t *testing.T) {
	s := newTestCallbackServer(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+s.state+"&code=abc123", nil)
	rec := httptest.NewRecorder()
	s.handleCallback(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Authorization code received") {
		t.Errorf("body = %q, want success message", rec.Body.String())
	}

	r := recvResult(t, s)
	if r.err != nil {
		t.Errorf("unexpected err: %v", r.err)
	}
	if r.code != "abc123" {
		t.Errorf("code = %q, want abc123", r.code)
	}
}

func TestHandleCallback_StateMismatchDoesNotAbort(t *testing.T) {
	s := newTestCallbackServer(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state=wrong&code=abc123", nil)
	rec := httptest.NewRecorder()
	s.handleCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	// Nothing must be sent on resultChan: the flow keeps waiting for a valid
	// callback rather than aborting on a stray/probe request.
	assertNoResult(t, s)
}

func TestHandleCallback_OAuthError(t *testing.T) {
	s := newTestCallbackServer(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+s.state+"&error=access_denied&error_description=denied+by+user", nil)
	rec := httptest.NewRecorder()
	s.handleCallback(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	r := recvResult(t, s)
	if r.err == nil {
		t.Fatal("expected an error result")
	}
	if !strings.Contains(r.err.Error(), "access_denied") || !strings.Contains(r.err.Error(), "denied by user") {
		t.Errorf("err = %v, want it to include the OAuth error code and description", r.err)
	}
}

func TestHandleCallback_MethodAndPath(t *testing.T) {
	s := newTestCallbackServer(t)

	// wrong method
	rec := httptest.NewRecorder()
	s.handleCallback(rec, httptest.NewRequest(http.MethodPost, "/oauth/callback?state="+s.state, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", rec.Code)
	}
	assertNoResult(t, s)

	// wrong path
	rec = httptest.NewRecorder()
	s.handleCallback(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("bad-path status = %d, want 404", rec.Code)
	}
	assertNoResult(t, s)
}

func recvResult(t *testing.T, s *oauthCallbackServer) oauthCallbackResult {
	t.Helper()
	select {
	case r := <-s.resultChan:
		return r
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for result on resultChan")
		return oauthCallbackResult{}
	}
}

func assertNoResult(t *testing.T, s *oauthCallbackServer) {
	t.Helper()
	select {
	case r := <-s.resultChan:
		t.Fatalf("unexpected result sent on resultChan: %+v", r)
	case <-time.After(50 * time.Millisecond):
	}
}
