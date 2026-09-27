package vault

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// newTestCallbackServer binds a callback server without serving it, so
// handlers can be called directly.
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
	if !strings.Contains(rec.Body.String(), "Request approved") {
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
	// the flow must keep waiting for a valid callback
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

	rec := httptest.NewRecorder()
	s.handleCallback(rec, httptest.NewRequest(http.MethodPost, "/oauth/callback?state="+s.state, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", rec.Code)
	}
	assertNoResult(t, s)

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

func TestHandleCallback_PageHeaders(t *testing.T) {
	s := newTestCallbackServer(t)

	rec := httptest.NewRecorder()
	s.handleCallback(rec, httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+s.state+"&code=abc123", nil))
	recvResult(t, s)

	for k, want := range map[string]string{
		"Content-Type":    "text/html; charset=utf-8",
		"Cache-Control":   "no-store",
		"Referrer-Policy": "no-referrer",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	for _, js := range []string{`history.replaceState(null, "", location.pathname)`, "window.close()", `<link rel="icon" href="data:image/svg+xml,`} {
		if !strings.Contains(rec.Body.String(), js) {
			t.Errorf("body = %q, want %s", rec.Body.String(), js)
		}
	}
}

// The PKCE flow closes the server as soon as it gets a result, so the page must
// already be on the wire by then.
func TestCallbackPageDeliveredBeforeShutdown(t *testing.T) {
	for i := 0; i < 200; i++ {
		s, err := newOauthCallbackServer()
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = s.Serve() }()
		closed := make(chan struct{})
		go func() {
			<-s.resultChan
			s.shutdown()
			close(closed)
		}()

		resp, err := http.Get(s.redirectURI() + "?state=" + s.state + "&error=access_denied")
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || !strings.Contains(string(body), "Sign-in failed") {
			t.Fatalf("run %d: body = %q, err = %v", i, body, err)
		}
		<-closed
	}
}

func TestDeviceCodeReason(t *testing.T) {
	sshVars := []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"}
	clearSSH := func(t *testing.T) {
		for _, v := range sshVars {
			t.Setenv(v, "")
		}
	}

	t.Run("pkce by default", func(t *testing.T) {
		clearSSH(t)
		if got := (&SSORoleCredentialsProvider{}).deviceCodeReason(); got != "" {
			t.Errorf("deviceCodeReason() = %q, want PKCE", got)
		}
	})
	t.Run("device code requested", func(t *testing.T) {
		clearSSH(t)
		if got := (&SSORoleCredentialsProvider{UseDeviceCode: true}).deviceCodeReason(); got == "" {
			t.Error("want device code when requested")
		}
	})
	t.Run("stdout", func(t *testing.T) {
		clearSSH(t)
		if got := (&SSORoleCredentialsProvider{UseStdout: true}).deviceCodeReason(); got == "" {
			t.Error("want device code with --stdout")
		}
	})
	for _, v := range sshVars {
		t.Run("ssh via "+v, func(t *testing.T) {
			clearSSH(t)
			t.Setenv(v, "set")
			if got := (&SSORoleCredentialsProvider{}).deviceCodeReason(); got == "" {
				t.Errorf("want device code when %s is set", v)
			}
		})
	}
}

func TestNewSSORoleCredentialsProvider_EndpointURL(t *testing.T) {
	for _, endpoint := range []string{"", "https://oidc.example.internal"} {
		cp, err := NewSSORoleCredentialsProvider(nil, &ProfileConfig{SSORegion: "eu-west-1", EndpointURL: endpoint}, false)
		if err != nil {
			t.Fatal(err)
		}
		got := aws.ToString(cp.(*SSORoleCredentialsProvider).OIDCClient.Options().BaseEndpoint)
		if got != endpoint {
			t.Errorf("EndpointURL %q: OIDC BaseEndpoint = %q, want %q", endpoint, got, endpoint)
		}
	}
}

func TestHandleCallback_RepeatedCallbackDoesNotBlock(t *testing.T) {
	s := newTestCallbackServer(t)
	req := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+s.state+"&code=abc123", nil)
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 3; i++ {
			s.handleCallback(httptest.NewRecorder(), req())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler blocked on a repeated callback")
	}
	if r := recvResult(t, s); r.code != "abc123" {
		t.Errorf("code = %q, want the first callback's", r.code)
	}
}

func TestHandleCallback_ErrorIsEscaped(t *testing.T) {
	s := newTestCallbackServer(t)

	rec := httptest.NewRecorder()
	s.handleCallback(rec, httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+s.state+"&error=%3Cb%3Ex%3C%2Fb%3E", nil))
	recvResult(t, s)

	if body := rec.Body.String(); strings.Contains(body, "<b>x</b>") || !strings.Contains(body, "&lt;b&gt;x&lt;/b&gt;") {
		t.Errorf("body = %q, want the error code HTML-escaped", body)
	}
}
