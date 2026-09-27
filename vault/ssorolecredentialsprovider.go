package vault

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/byteness/keyring"
	"github.com/skratchdot/open-golang/open"
)

type OIDCTokenCacher interface {
	Get(string) (*ssooidc.CreateTokenOutput, error)
	Set(string, *ssooidc.CreateTokenOutput) error
	Remove(string) error
}

// SSORoleCredentialsProvider creates temporary credentials for an SSO Role.
type SSORoleCredentialsProvider struct {
	OIDCClient     *ssooidc.Client
	OIDCTokenCache OIDCTokenCacher
	StartURL       string
	SSOClient      *sso.Client
	AccountID      string
	RoleName       string
	UseStdout      bool
	UseDeviceCode  bool
}

// pollSleep is a variable so tests can replace it.
var pollSleep = time.Sleep

func millisecondsTimeValue(v int64) time.Time {
	return time.Unix(0, v*int64(time.Millisecond))
}

// Retrieve generates a new set of temporary credentials using SSO GetRoleCredentials.
func (p *SSORoleCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := p.getRoleCredentials(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		CanExpire:       true,
		Expires:         millisecondsTimeValue(creds.Expiration),
	}, nil
}

func (p *SSORoleCredentialsProvider) getRoleCredentials(ctx context.Context) (*ssotypes.RoleCredentials, error) {
	token, cached, err := p.getOIDCToken(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := p.SSOClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: token.AccessToken,
		AccountId:   aws.String(p.AccountID),
		RoleName:    aws.String(p.RoleName),
	})
	if err != nil {
		if cached && p.OIDCTokenCache != nil {
			var rspError *awshttp.ResponseError
			if !errors.As(err, &rspError) {
				return nil, err
			}

			// If the error is a 401, remove the cached oidc token and try
			// again. This is a recursive call but it should only happen once
			// due to the cache being cleared before retrying.
			if rspError.HTTPStatusCode() == http.StatusUnauthorized {
				err = p.OIDCTokenCache.Remove(p.StartURL)
				if err != nil {
					return nil, err
				}
				return p.getRoleCredentials(ctx)
			}
		}
		return nil, err
	}
	log.Printf("Got credentials %s for SSO role %s (account: %s), expires in %s", FormatKeyForDisplay(*resp.RoleCredentials.AccessKeyId), p.RoleName, p.AccountID, time.Until(millisecondsTimeValue(resp.RoleCredentials.Expiration)).String())

	return resp.RoleCredentials, nil
}

func (p *SSORoleCredentialsProvider) RetrieveStsCredentials(ctx context.Context) (*ststypes.Credentials, error) {
	return p.getRoleCredentialsAsStsCredemtials(ctx)
}

// getRoleCredentialsAsStsCredemtials returns getRoleCredentials as sts.Credentials because sessions.Store expects it
func (p *SSORoleCredentialsProvider) getRoleCredentialsAsStsCredemtials(ctx context.Context) (*ststypes.Credentials, error) {
	creds, err := p.getRoleCredentials(ctx)
	if err != nil {
		return nil, err
	}

	return &ststypes.Credentials{
		AccessKeyId:     creds.AccessKeyId,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      aws.Time(millisecondsTimeValue(creds.Expiration)),
	}, nil
}

func (p *SSORoleCredentialsProvider) getOIDCToken(ctx context.Context) (token *ssooidc.CreateTokenOutput, cached bool, err error) {
	if p.OIDCTokenCache != nil {
		token, err = p.OIDCTokenCache.Get(p.StartURL)
		if err != nil && err != keyring.ErrKeyNotFound {
			return nil, false, err
		}
		if token != nil {
			return token, true, nil
		}
	}

	if reason := p.deviceCodeReason(); reason != "" {
		log.Printf("Using the OIDC device code flow: %s", reason)
		token, err = p.newOIDCTokenDeviceCode(ctx)
	} else {
		token, err = p.newOIDCTokenPKCE(ctx)
	}
	if err != nil {
		return nil, false, err
	}

	if p.OIDCTokenCache != nil {
		err = p.OIDCTokenCache.Set(p.StartURL, token)
		if err != nil {
			return nil, false, err
		}
	}
	return token, false, err
}

// deviceCodeReason returns why to use the device code flow instead of PKCE, or
// "". PKCE redirects to this machine's 127.0.0.1, which a browser on another
// machine cannot reach.
func (p *SSORoleCredentialsProvider) deviceCodeReason() string {
	switch {
	case p.UseDeviceCode:
		return "requested with --device-code"
	case p.UseStdout:
		return "--stdout is set, so the browser may not run on this machine"
	case inSSHSession():
		return "running in an SSH session"
	}
	return ""
}

func inSSHSession() bool {
	for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if os.Getenv(v) != "" {
			return true
		}
	}
	return false
}

func (p *SSORoleCredentialsProvider) newOIDCTokenDeviceCode(ctx context.Context) (*ssooidc.CreateTokenOutput, error) {
	clientCreds, err := p.OIDCClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("aws-vault"),
		ClientType: aws.String("public"),
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Created new OIDC client (expires at: %s)", time.Unix(clientCreds.ClientSecretExpiresAt, 0))

	deviceCreds, err := p.OIDCClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     clientCreds.ClientId,
		ClientSecret: clientCreds.ClientSecret,
		StartUrl:     aws.String(p.StartURL),
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Created OIDC device code for %s (expires in: %ds)", p.StartURL, deviceCreds.ExpiresIn)

	p.openOrPrintURL(aws.ToString(deviceCreds.VerificationUriComplete))

	// These are the default values defined in the following RFC:
	// https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.5
	var slowDownDelay = 5 * time.Second
	var retryInterval = 5 * time.Second

	if i := deviceCreds.Interval; i > 0 {
		retryInterval = time.Duration(i) * time.Second
	}

	for {
		t, err := p.OIDCClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     clientCreds.ClientId,
			ClientSecret: clientCreds.ClientSecret,
			DeviceCode:   deviceCreds.DeviceCode,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
		})
		if err != nil {
			var sde *ssooidctypes.SlowDownException
			var ape *ssooidctypes.AuthorizationPendingException
			switch {
			case errors.As(err, &sde):
				retryInterval += slowDownDelay
			case !errors.As(err, &ape):
				return nil, err
			}
			pollSleep(retryInterval)
			continue
		}

		log.Printf("Created new OIDC access token for %s (expires in: %ds)", p.StartURL, t.ExpiresIn)
		return t, nil
	}
}

// newOIDCTokenPKCE generates a new OIDC token using the authorization code flow
// with PKCE (https://datatracker.ietf.org/doc/html/rfc7636).
func (p *SSORoleCredentialsProvider) newOIDCTokenPKCE(ctx context.Context) (*ssooidc.CreateTokenOutput, error) {
	codeVerifierBytes := make([]byte, 32)
	if _, err := crand.Read(codeVerifierBytes); err != nil {
		return nil, fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(codeVerifierBytes)

	codeChallengeBytes := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:])
	log.Printf("Generated PKCE code_challenge: %q", codeChallenge)

	clientCreds, err := p.OIDCClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName:   aws.String("aws-vault"),
		ClientType:   aws.String("public"),
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"sso:account:access"},
		IssuerUrl:    aws.String(p.StartURL),
		RedirectUris: []string{"http://127.0.0.1/oauth/callback"},
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Created new OIDC client (expires at: %s)", time.Unix(clientCreds.ClientSecretExpiresAt, 0))

	cbServer, err := newOauthCallbackServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create oauthCallbackServer: %w", err)
	}
	log.Printf("oauthCallbackServer callback endpoint: %s", cbServer.redirectURI())
	defer func() {
		if err := cbServer.h.Close(); err != nil {
			log.Printf("Failed to close oauthCallbackServer: %s", err)
		}
	}()
	go func() {
		if err := cbServer.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("Failed to run oauthCallbackServer: %s", err)
		}
	}()
	// the authorize URL and CreateToken must use the same redirect URI
	redirectURI := cbServer.redirectURI()

	args := url.Values{
		"client_id":             {aws.ToString(clientCreds.ClientId)},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"state":                 {cbServer.state},
		"code_challenge_method": {"S256"},
		"code_challenge":        {codeChallenge},
		"scopes":                {"sso:account:access"},
	}
	// /authorize is not a modeled API operation, so build its URL by hand.
	// BaseEndpoint is a full URL, not a host.
	authorizeURL := &url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("oidc.%s.amazonaws.com", p.OIDCClient.Options().Region),
	}
	if base := aws.ToString(p.OIDCClient.Options().BaseEndpoint); base != "" {
		u, err := url.Parse(base)
		if err != nil {
			return nil, fmt.Errorf("failed to parse OIDC base endpoint %q: %w", base, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("OIDC base endpoint %q is not an absolute URL", base)
		}
		authorizeURL = u
	}
	// JoinPath keeps any path prefix of the base endpoint
	authorizeURL = authorizeURL.JoinPath("authorize")
	authorizeURL.RawQuery = args.Encode()
	log.Printf("Authorize URL: %s", authorizeURL.String())

	p.openOrPrintURL(authorizeURL.String())

	var r oauthCallbackResult
	select {
	case r = <-cbServer.resultChan:
	case <-ctx.Done():
		return nil, fmt.Errorf("aborted waiting for OAuth callback: %w", ctx.Err())
	}

	if r.err != nil {
		return nil, r.err
	}
	if r.code == "" {
		return nil, errors.New("no authorization code received")
	}

	tok, err := p.OIDCClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     clientCreds.ClientId,
		ClientSecret: clientCreds.ClientSecret,
		Code:         aws.String(r.code),
		CodeVerifier: aws.String(codeVerifier),
		GrantType:    aws.String("authorization_code"),
		RedirectUri:  aws.String(redirectURI),
	})
	if err != nil {
		return nil, err
	}

	log.Printf("Created new OIDC access token for %s (expires in: %ds)", p.StartURL, tok.ExpiresIn)
	return tok, nil
}

// openBrowser is a variable so tests can replace it.
var openBrowser = open.Run

// openOrPrintURL opens the URL in the default browser, or only prints it to stderr if UseStdout is set.
func (p *SSORoleCredentialsProvider) openOrPrintURL(url string) {
	if p.UseStdout {
		fmt.Fprintf(os.Stderr, "Open the SSO authorization page in a browser (use Ctrl-C to abort)\n%s\n", url)
	} else {
		fmt.Fprintf(os.Stderr, "Opening the SSO authorization page in your default browser (use Ctrl-C to abort)\n%s\n", url)
		log.Println("Opening SSO authorization page in browser")
		if err := openBrowser(url); err != nil {
			log.Printf("Failed to open browser: %s", err)
		}
	}
}

// newOauthCallbackServer binds a random loopback port for the OAuth2 callback,
// which reports the authorization code on resultChan.
func newOauthCallbackServer() (*oauthCallbackServer, error) {
	// loopback only: the callback carries the authorization code
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}
	log.Printf("oauthCallbackListener listening on %s", ln.Addr().String())

	state := make([]byte, 32)
	if _, err := crand.Read(state); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	oauth := &oauthCallbackServer{
		state:      base64.RawURLEncoding.EncodeToString(state),
		resultChan: make(chan oauthCallbackResult, 1),
		ln:         ln,
	}
	oauth.h = &http.Server{
		Handler: http.HandlerFunc(oauth.handleCallback),
	}

	return oauth, nil
}

// handleCallback handles the OAuth2 callback request and sends the authorization code to the server channel.
func (s *oauthCallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/oauth/callback" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// a wrong or missing state (e.g. a port probe) is rejected without ending
	// the flow, as in the AWS CLI
	state := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(state), []byte(s.state)) != 1 {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// an OAuth2 error instead of a code, e.g. the user denied access
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		errDesc := r.URL.Query().Get("error_description")
		writeCallbackPage(w, "Authorization failed, you can close this tab now.")
		s.report(oauthCallbackResult{err: fmt.Errorf("authorization error: %s: %s", errCode, errDesc)})
		return
	}

	code := r.URL.Query().Get("code")
	writeCallbackPage(w, "Authorization code received, you can close this tab now.")
	s.report(oauthCallbackResult{code: code})
}

// report sends the first result only, so a repeated callback (e.g. a reload)
// can't block its handler once the flow stops reading.
func (s *oauthCallbackServer) report(r oauthCallbackResult) {
	select {
	case s.resultChan <- r:
	default:
	}
}

// The script drops the authorization code from the address bar, then tries to
// close the tab. Browsers only allow that if script opened the tab or the page
// is its only history entry, which the SSO sign-in pages usually rule out.
const callbackPage = `<!doctype html>
<html><head><meta charset="utf-8"><title>aws-vault</title></head>
<body><p>%s</p><script>history.replaceState(null, "", location.pathname); window.close()</script></body></html>
`

// writeCallbackPage flushes because the caller signals the result next, and the
// receiver may then close the connection before the reply is sent.
func writeCallbackPage(w http.ResponseWriter, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	// the callback URL carries the authorization code
	h.Set("Referrer-Policy", "no-referrer")
	fmt.Fprintf(w, callbackPage, html.EscapeString(msg))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// redirectURI returns the URL for the OAuth callback endpoint with the server's port included in the address.
func (s *oauthCallbackServer) redirectURI() string {
	// the host must match the registered redirect URI
	u := url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("127.0.0.1:%d", s.ln.Addr().(*net.TCPAddr).Port),
		Path:   "/oauth/callback",
	}
	return u.String()
}

type oauthCallbackResult struct {
	code string
	err  error
}

type oauthCallbackServer struct {
	ln net.Listener
	h  *http.Server

	// secret used to prevent CSRF attacks
	state string
	// channel to send authorization code after successful callback
	resultChan chan oauthCallbackResult
}

func (s *oauthCallbackServer) Serve() error {
	return s.h.Serve(s.ln)
}
