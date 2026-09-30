package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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
			var in struct{ Scopes []string }
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !reflect.DeepEqual(in.Scopes, []string{"sso:account:access"}) {
				t.Errorf("registered with scopes %v (%v), want sso:account:access for a refresh token", in.Scopes, err)
			}
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
