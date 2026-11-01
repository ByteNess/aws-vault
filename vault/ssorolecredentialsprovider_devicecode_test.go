package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

// RFC 8628 §3.5: on slow_down, keep polling with the interval increased by 5s.
func TestDeviceCodeSlowDown(t *testing.T) {
	tokenReplies := []string{"SlowDownException", "AuthorizationPendingException", ""}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var out any
		switch r.URL.Path {
		case "/client/register":
			out = map[string]any{"clientId": "client-id", "clientSecret": "client-secret", "clientSecretExpiresAt": time.Now().Add(time.Hour).Unix()}
		case "/device_authorization":
			out = map[string]any{"deviceCode": "device-code", "userCode": "CODE", "verificationUriComplete": "https://example.com/device", "expiresIn": 600, "interval": 1}
		case "/token":
			reply := tokenReplies[0]
			tokenReplies = tokenReplies[1:]
			if reply != "" {
				w.Header().Set("X-Amzn-ErrorType", reply)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			out = map[string]any{"accessToken": "access-token", "tokenType": "Bearer", "expiresIn": 3600}
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)

	var slept []time.Duration
	orig := pollSleep
	t.Cleanup(func() { pollSleep = orig })
	pollSleep = func(d time.Duration) { slept = append(slept, d) }

	p := &SSORoleCredentialsProvider{
		OIDCClient: ssooidc.New(ssooidc.Options{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL)}),
		StartURL:   "https://d-1234567890.awsapps.com/start",
		UseStdout:  true,
	}
	tok, _, err := p.getOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("getOIDCToken: %v", err)
	}
	if aws.ToString(tok.AccessToken) != "access-token" {
		t.Errorf("access token = %q, want access-token", aws.ToString(tok.AccessToken))
	}
	if want := []time.Duration{6 * time.Second, 6 * time.Second}; !reflect.DeepEqual(slept, want) {
		t.Errorf("polled after %v, want %v", slept, want)
	}
}

// IAM Identity Center can return a request_uri verification URL that omits
// the user code.
func TestDeviceCodePrintsUserCode(t *testing.T) {
	const requestURI = "https://eu-west-1.signin.aws/platform/authorize?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc"
	for _, tc := range []struct {
		name     string
		userCode string
		want     string
	}{
		{name: "user code", userCode: "WXYZ-1234", want: "Confirm the SSO authorization page shows this code: WXYZ-1234\n"},
		{name: "no user code", userCode: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var out any
				switch r.URL.Path {
				case "/client/register":
					out = map[string]any{"clientId": "client-id", "clientSecret": "client-secret", "clientSecretExpiresAt": time.Now().Add(time.Hour).Unix()}
				case "/device_authorization":
					out = map[string]any{"deviceCode": "device-code", "userCode": tc.userCode, "verificationUriComplete": requestURI, "expiresIn": 600, "interval": 1}
				case "/token":
					out = map[string]any{"accessToken": "access-token", "tokenType": "Bearer", "expiresIn": 3600}
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			t.Cleanup(srv.Close)

			var stderr bytes.Buffer
			p := &SSORoleCredentialsProvider{
				OIDCClient: ssooidc.New(ssooidc.Options{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL)}),
				StartURL:   "https://d-1234567890.awsapps.com/start",
				UseStdout:  true,
				stderr:     &stderr,
			}
			if _, _, err := p.getOIDCToken(context.Background()); err != nil {
				t.Fatalf("getOIDCToken: %v", err)
			}

			got := stderr.String()
			wantURL := "Open the SSO authorization page in a browser (use Ctrl-C to abort)\n" + requestURI + "\n"
			if !strings.HasPrefix(got, wantURL) {
				t.Fatalf("stderr = %q, want prefix %q", got, wantURL)
			}
			if rest := strings.TrimPrefix(got, wantURL); rest != tc.want {
				t.Errorf("after the URL, stderr = %q, want %q", rest, tc.want)
			}
		})
	}
}
