package vault

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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

	// use the device code flow only if we have been requested to, otherwise
	// default to the PKCE authorization code flow.
	if p.UseDeviceCode {
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
			if errors.As(err, &sde) {
				retryInterval += slowDownDelay
			}

			var ape *ssooidctypes.AuthorizationPendingException
			if errors.As(err, &ape) {
				time.Sleep(retryInterval)
				continue
			}

			return nil, err
		}

		log.Printf("Created new OIDC access token for %s (expires in: %ds)", p.StartURL, t.ExpiresIn)
		return t, nil
	}
}

// newOIDCTokenPKCE generates a new OIDC token using the "Authorization Code Grant" flow with PKCE.
func (p *SSORoleCredentialsProvider) newOIDCTokenPKCE(ctx context.Context) (*ssooidc.CreateTokenOutput, error) {
	// ref: https://datatracker.ietf.org/doc/html/rfc7636

	// generate a random 32 byte code verifier; base64 encode it
	codeVerifierBytes := make([]byte, 32)
	n, err := crand.Read(codeVerifierBytes)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(codeVerifierBytes)

	// generate the code challenge: base64(sha256(codeVerifier))
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

	// start the callback server
	cbServer, err := newOauthCallbackServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create oauthCallbackServer: %w", err)
	}
	log.Printf("oauthCallbackServer callback endpoint: %s", cbServer.redirectURI())
	// ensure the callback server is torn down on any exit path
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
	// redirectURI is used in both the authorize URL and the later CreateToken call;
	// bind it once so both sides agree on the same value.
	redirectURI := cbServer.redirectURI()

	// construct the authorize URL with the client and PKCE parameters
	args := url.Values{
		"client_id":             {aws.ToString(clientCreds.ClientId)},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"state":                 {cbServer.state},
		"code_challenge_method": {"S256"},
		"code_challenge":        {codeChallenge},
		"scopes":                {"sso:account:access"},
	}
	// prefer the base endpoint from client options, otherwise use a default
	var host string
	if p.OIDCClient.Options().BaseEndpoint != nil && *p.OIDCClient.Options().BaseEndpoint != "" {
		host = *p.OIDCClient.Options().BaseEndpoint
	} else {
		host = fmt.Sprintf("oidc.%s.amazonaws.com", p.OIDCClient.Options().Region)
	}
	authorizeURL := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     "/authorize",
		RawQuery: args.Encode(),
	}
	log.Printf("Authorize URL: %s", authorizeURL.String())

	p.openOrPrintURL(authorizeURL.String())

	// await the authorization code, or context cancellation
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

	// create the OIDC token using the authorization code received from the callback server
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

// openOrPrintURL opens the URL in the default browser or prints it to stdout if UseStdout is set.
func (p *SSORoleCredentialsProvider) openOrPrintURL(url string) {
	if p.UseStdout {
		fmt.Fprintf(os.Stderr, "Open the SSO authorization page in a browser (use Ctrl-C to abort)\n%s\n", url)
	} else {
		fmt.Fprintf(os.Stderr, "Opening the SSO authorization page in your default browser (use Ctrl-C to abort)\n%s\n", url)
		log.Println("Opening SSO authorization page in browser")
		if err := open.Run(url); err != nil {
			log.Printf("Failed to open browser: %s", err)
		}
	}
}

// newOauthCallbackServer creates a HTTP server listening on a random localhost
// port to serve the OAuth2 callback. It serves a single oauth callback endpoint
// and sends the authorization code received via a channel.
func newOauthCallbackServer() (*oauthCallbackServer, error) {
	// select a random port for the callback server
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}
	log.Printf("oauthCallbackListener listening on %s", ln.Addr().String())

	// create a 32 byte state for CSRF protection
	state := make([]byte, 32)
	n, err := crand.Read(state)
	if err != nil || n != 32 {
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
	// only respond to GET requests on the callback
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/oauth/callback" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// constant time string comparison of want vs got state
	state := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(state), []byte(s.state)) != 1 {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		s.resultChan <- oauthCallbackResult{err: errors.New("invalid state")}
		return
	}

	// respond with a success message before signalling completion, so the
	// response is fully written before the main goroutine tears the server down
	code := r.URL.Query().Get("code")
	io.WriteString(w, "Authorization code received, you can close this tab now.")
	s.resultChan <- oauthCallbackResult{code: code}
}

// redirectURI returns the URL for the OAuth callback endpoint with the server's port included in the address.
func (s *oauthCallbackServer) redirectURI() string {
	// AWS requires that the callback be a 127.0.0.1 v4 address
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
