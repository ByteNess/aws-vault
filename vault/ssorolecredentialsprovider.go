package vault

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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

// OIDCTokenCacher caches OIDC access tokens by SSO start URL.
type OIDCTokenCacher interface {
	Get(string) (*OIDCTokenData, error)
	Set(string, *OIDCTokenData) error
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
	Browser        string
	// RegistrationScopes are the OAuth scopes requested when registering the
	// OIDC client (sso_registration_scopes). With scopes such as
	// sso:account:access, IAM Identity Center returns a refresh token alongside
	// the access token, so an expired token is renewed without a browser until
	// the Identity Center session itself ends.
	RegistrationScopes []string
	UseSSOTokenLock    bool
	ssoTokenLock       ProcessLock
	ssoLockWait        time.Duration
	ssoLockLog         time.Duration
	ssoLockTimeout     time.Duration
	ssoNow             func() time.Time
	ssoSleep           func(context.Context, time.Duration) error
	ssoLogf            lockLogger
	newOIDCTokenFn     func(context.Context) (*OIDCTokenData, error)
}

// pollSleep is a variable so tests can replace it.
var pollSleep = time.Sleep

func millisecondsTimeValue(v int64) time.Time {
	return time.Unix(0, v*int64(time.Millisecond))
}

const (
	// defaultSSOLockWaitDelay is the polling interval between lock attempts.
	// 100ms keeps latency low for the typical case where the lock holder
	// finishes quickly (browser auth + token cache write).
	defaultSSOLockWaitDelay = 100 * time.Millisecond

	// defaultSSOLockLogEvery controls how often we emit a debug log while
	// waiting for the lock. 15s avoids log spam while still showing progress
	// during long waits (e.g. slow browser auth).
	defaultSSOLockLogEvery = 15 * time.Second

	// defaultSSOLockWarnAfter is the delay before printing a user-visible
	// "waiting for lock" message to stderr. 5s is long enough to avoid
	// flashing the message on normal lock contention, short enough to
	// reassure the user that the process isn't hung.
	defaultSSOLockWarnAfter = 5 * time.Second

	// defaultSSOLockTimeout is a safety net: if the lock holder is hung
	// (e.g. a browser auth that was abandoned), waiters give up after this
	// duration rather than blocking indefinitely. 2 minutes matches the
	// keyring lock timeout.
	defaultSSOLockTimeout = 2 * time.Minute

	// ssoRetryTimeout is a pathological safety net: if GetRoleCredentials is still
	// returning 429s after this duration, give up and surface the error to the user.
	// 5 minutes is generous but accommodates burst-heavy credential_process workloads
	// (e.g. Terraform with hundreds of parallel invocations).
	ssoRetryTimeout = 5 * time.Minute

	// ssoRetryBase is the initial backoff delay before the first retry.
	// 200ms is short enough to avoid unnecessary latency on transient 429s
	// while still giving the SSO service breathing room.
	ssoRetryBase = 200 * time.Millisecond

	// ssoRetryMax caps the exponential backoff so that individual waits
	// don't grow unreasonably large between attempts.
	ssoRetryMax = 5 * time.Second

	// ssoRetryAfterJitterMin and ssoRetryAfterJitterMax define the full-jitter
	// range as a multiplier of the base delay. The raw range 0.5x-1.5x
	// decorrelates concurrent processes that all received the same
	// Retry-After header. jitterRetryAfter clamps the result to >= base so
	// the server's requested minimum is always respected; jitteredBackoff
	// uses the full range for exponential backoff.
	ssoRetryAfterJitterMin = 0.5
	ssoRetryAfterJitterMax = 1.5
)

// initSSODefaults sets production defaults for all internal dependencies.
// Called by the constructor; tests can override unexported fields afterward.
func (p *SSORoleCredentialsProvider) initSSODefaults() {
	p.ssoLockWait = defaultSSOLockWaitDelay
	p.ssoLockLog = defaultSSOLockLogEvery
	p.ssoLockTimeout = defaultSSOLockTimeout
	p.ssoNow = time.Now
	p.ssoSleep = defaultContextSleep
	p.ssoLogf = log.Printf
	p.newOIDCTokenFn = p.newOIDCToken
}

// EnableSSOTokenLock creates the SSO token lock for cross-process coordination.
// Called at construction time when parallelSafe is true. Every sign-in flow is
// covered: PKCE, the device code flow, and --stdout, which selects the device
// code flow and still starts one device authorization per process.
func (p *SSORoleCredentialsProvider) EnableSSOTokenLock() {
	p.UseSSOTokenLock = true
	if p.ssoTokenLock == nil {
		p.ssoTokenLock = NewDefaultLock("aws-vault.sso", p.StartURL)
	}
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

	baseDelay, maxDelay := ssoRetryBase, ssoRetryMax
	deadline := p.ssoNow().Add(ssoRetryTimeout)
	attempt := 0
	rateLimitCount := 0
	var maxRetryAfterSeen time.Duration
	for {
		attempt++
		resp, err := p.SSOClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
			AccessToken: token.AccessToken,
			AccountId:   aws.String(p.AccountID),
			RoleName:    aws.String(p.RoleName),
		})
		if err == nil {
			log.Printf("Got credentials %s for SSO role %s (account: %s), expires in %s", FormatKeyForDisplay(*resp.RoleCredentials.AccessKeyId), p.RoleName, p.AccountID, time.Until(millisecondsTimeValue(resp.RoleCredentials.Expiration)).String())
			return resp.RoleCredentials, nil
		}

		if cached && p.OIDCTokenCache != nil {
			var rspError *awshttp.ResponseError
			if errors.As(err, &rspError) && rspError.HTTPStatusCode() == http.StatusUnauthorized {
				// Cached token rejected: drop it and retry with a fresh access token.
				// This should only happen once because the cache is cleared before retrying.
				if err = p.OIDCTokenCache.Remove(p.StartURL); err != nil {
					return nil, err
				}
				token, cached, err = p.getOIDCToken(ctx)
				if err != nil {
					return nil, err
				}
				attempt = 0
				continue
			}
		}

		if isSSORateLimitError(err) {
			rateLimitCount++
			remaining := deadline.Sub(p.ssoNow())
			if 0 < remaining {
				var delay time.Duration
				if retryAfter, ok := retryAfterFromError(err); ok {
					if maxRetryAfterSeen < retryAfter {
						maxRetryAfterSeen = retryAfter
					}
					delay = jitterRetryAfter(retryAfter)
				} else {
					delay = jitteredBackoff(baseDelay, maxDelay, attempt)
				}
				if remaining < delay {
					delay = remaining
				}
				log.Printf("SSO rate limited for role %s (account: %s); backing off %s, attempt %d (%d 429s, max retry-after %s)", p.RoleName, p.AccountID, delay, attempt, rateLimitCount, maxRetryAfterSeen)
				if err = p.ssoSleep(ctx, delay); err != nil {
					return nil, err
				}
				continue
			}
			return nil, fmt.Errorf("SSO rate limited for role %s (account: %s) persistently for %s (%d 429s, max retry-after %s); giving up — try again later: %w", p.RoleName, p.AccountID, ssoRetryTimeout, rateLimitCount, maxRetryAfterSeen, err)
		}

		return nil, err
	}
}

// RetrieveStsCredentials returns the SSO role credentials in STS form.
func (p *SSORoleCredentialsProvider) RetrieveStsCredentials(ctx context.Context) (*ststypes.Credentials, error) {
	return p.getRoleCredentialsAsStsCredentials(ctx)
}

// getRoleCredentialsAsStsCredentials returns getRoleCredentials as sts.Credentials because sessions.Store expects it
func (p *SSORoleCredentialsProvider) getRoleCredentialsAsStsCredentials(ctx context.Context) (*ststypes.Credentials, error) {
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

// oidcRefreshWindow is how long before expiry a refreshable token is renewed.
// It matches the AWS CLI's SSOTokenProvider and keeps GetRoleCredentials from
// being handed a token with seconds left, whose 401 would drop the cached
// entry (refresh token included) and force a browser login.
const oidcRefreshWindow = 15 * time.Minute

func (p *SSORoleCredentialsProvider) getOIDCToken(ctx context.Context) (token *ssooidc.CreateTokenOutput, cached bool, err error) {
	token, cached, needLogin, err := p.cachedOrRefreshedOIDCToken(ctx)
	if err != nil || !needLogin {
		return token, cached, err
	}

	if !p.UseSSOTokenLock {
		return p.createAndCacheOIDCToken(ctx)
	}

	return p.getOIDCTokenWithLock(ctx)
}

// cachedOrRefreshedOIDCToken returns a usable token from the cache, refreshing
// it when it has expired or is about to. needLogin reports that a new sign-in
// is the only way forward.
func (p *SSORoleCredentialsProvider) cachedOrRefreshedOIDCToken(ctx context.Context) (token *ssooidc.CreateTokenOutput, cached bool, needLogin bool, err error) {
	if p.OIDCTokenCache == nil {
		return nil, false, true, nil
	}

	data, err := p.OIDCTokenCache.Get(p.StartURL)
	if err != nil && err != keyring.ErrKeyNotFound {
		return nil, false, false, err
	}
	if data == nil {
		return nil, false, true, nil
	}

	token, needLogin, err = p.cachedOIDCToken(ctx, data)
	if err != nil {
		return nil, false, false, err
	}
	if needLogin {
		return nil, false, true, nil
	}
	return token, true, false, nil
}

// validCachedOIDCToken is the read-only check used while waiting for the SSO
// lock. It never refreshes and never signs in, so waiters poll the keyring
// instead of the OIDC service while the holder does the work.
func (p *SSORoleCredentialsProvider) validCachedOIDCToken() (token *ssooidc.CreateTokenOutput, ok bool, err error) {
	if p.OIDCTokenCache == nil {
		return nil, false, nil
	}

	data, err := p.OIDCTokenCache.Get(p.StartURL)
	if err != nil && err != keyring.ErrKeyNotFound {
		return nil, false, err
	}
	if data == nil || data.Expired() {
		return nil, false, nil
	}
	return &data.Token, true, nil
}

// signIn creates a token through newOIDCTokenFn when the constructor wired it
// up, which is the seam the lock tests stand in on, and falls back to the real
// sign-in flows for providers assembled directly.
func (p *SSORoleCredentialsProvider) signIn(ctx context.Context) (*OIDCTokenData, error) {
	if p.newOIDCTokenFn != nil {
		return p.newOIDCTokenFn(ctx)
	}
	return p.newOIDCToken(ctx)
}

// newOIDCToken signs in with whichever flow applies: the authorization code
// flow with PKCE by default, the device code flow when the browser may not
// reach the local callback. Both go through here, so the SSO lock serialises
// the two the same way.
func (p *SSORoleCredentialsProvider) newOIDCToken(ctx context.Context) (*OIDCTokenData, error) {
	if reason := p.deviceCodeReason(); reason != "" {
		log.Printf("Using the OIDC device code flow: %s", reason)
		return p.newOIDCTokenDeviceCode(ctx)
	}
	return p.newOIDCTokenPKCE(ctx)
}

func (p *SSORoleCredentialsProvider) createAndCacheOIDCToken(ctx context.Context) (token *ssooidc.CreateTokenOutput, cached bool, err error) {
	data, err := p.signIn(ctx)
	if err != nil {
		return nil, false, err
	}

	if p.OIDCTokenCache != nil {
		if err = p.OIDCTokenCache.Set(p.StartURL, data); err != nil {
			return nil, false, err
		}
	}
	return &data.Token, false, nil
}

type oidcTokenResult struct {
	token  *ssooidc.CreateTokenOutput
	cached bool
}

// getOIDCTokenWithLock serialises the sign-in across processes: one process
// holds the lock and signs in (or redeems the refresh token) while the others
// wait, re-reading the cache until the token lands.
func (p *SSORoleCredentialsProvider) getOIDCTokenWithLock(ctx context.Context) (token *ssooidc.CreateTokenOutput, cached bool, err error) {
	waitCtx, cancel := context.WithTimeout(ctx, p.ssoLockTimeout)
	defer cancel()

	result, err := withProcessLock(waitCtx, p.ssoTokenLock, lockWaiterOpts{
		LockPath:  p.ssoTokenLock.Path(),
		WarnMsg:   "Waiting for SSO lock at %s\n",
		LogMsg:    "Waiting for SSO lock at %s",
		WaitDelay: p.ssoLockWait,
		LogEvery:  p.ssoLockLog,
		WarnAfter: defaultSSOLockWarnAfter,
		Now:       p.ssoNow,
		Sleep:     p.ssoSleep,
		Logf:      p.ssoLogf,
		Warnf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	}, "SSO token", func() (processLockResult[oidcTokenResult], error) {
		token, ok, err := p.validCachedOIDCToken()
		if err != nil {
			return processLockResult[oidcTokenResult]{}, err
		}
		if ok {
			return processLockResult[oidcTokenResult]{value: oidcTokenResult{token, true}, ok: true}, nil
		}
		return processLockResult[oidcTokenResult]{}, nil
	}, func() (oidcTokenResult, error) {
		// Recheck under the lock — another process may have filled the cache,
		// and the refresh token is redeemed here so only one process spends it.
		token, cached, needLogin, err := p.cachedOrRefreshedOIDCToken(ctx)
		if err != nil {
			return oidcTokenResult{}, err
		}
		if !needLogin {
			return oidcTokenResult{token, cached}, nil
		}

		data, err := p.signIn(ctx)
		if err != nil {
			return oidcTokenResult{}, err
		}

		if p.OIDCTokenCache != nil {
			if err = p.OIDCTokenCache.Set(p.StartURL, data); err != nil {
				return oidcTokenResult{}, err
			}
		}

		return oidcTokenResult{&data.Token, false}, nil
	})
	return result.token, result.cached, err
}

// cachedOIDCToken decides what to do with a cached entry: use it, refresh it,
// or report that a new login is needed. It is safe against several processes
// sharing one cache: a refresh token is single use, so when a refresh is
// rejected the cache is re-read before anything is removed, and a transient
// error keeps the refresh token for the next attempt.
func (p *SSORoleCredentialsProvider) cachedOIDCToken(ctx context.Context, data *OIDCTokenData) (token *ssooidc.CreateTokenOutput, needLogin bool, err error) {
	expiresSoon := time.Until(data.Expiration) < oidcRefreshWindow
	if !data.Expired() && !expiresSoon {
		return &data.Token, false, nil
	}
	if !data.Refreshable() {
		if !data.Expired() {
			return &data.Token, false, nil
		}
		log.Printf("OIDC token for %s expired and cannot be refreshed, starting a new login", p.StartURL)
		if err := p.OIDCTokenCache.Remove(p.StartURL); err != nil && err != keyring.ErrKeyNotFound {
			return nil, false, err
		}
		return nil, true, nil
	}

	refreshed, refreshErr := p.refreshOIDCToken(ctx, data)
	if refreshErr == nil {
		if err := p.OIDCTokenCache.Set(p.StartURL, refreshed); err != nil {
			return nil, false, err
		}
		return &refreshed.Token, false, nil
	}
	if !data.Expired() {
		log.Printf("Refreshing OIDC token for %s failed, using the current token (expires in %s): %s", p.StartURL, time.Until(data.Expiration).Round(time.Second), refreshErr)
		return &data.Token, false, nil
	}

	// Another process may have refreshed the same entry in the meantime, in
	// which case our refresh token was already consumed and the cache now holds
	// a valid token that must not be discarded.
	current, getErr := p.OIDCTokenCache.Get(p.StartURL)
	if getErr == nil && current != nil && !current.Expired() {
		log.Printf("OIDC token for %s was refreshed by another process, using it", p.StartURL)
		return &current.Token, false, nil
	}
	if !isOIDCRejection(refreshErr) {
		return nil, false, fmt.Errorf("refreshing OIDC token for %s: %w", p.StartURL, refreshErr)
	}
	log.Printf("Refreshing OIDC token for %s was rejected, starting a new login: %s", p.StartURL, refreshErr)
	// Remove only the entry we tried to redeem; anything else was written by
	// someone else and is theirs to manage.
	if getErr == nil && current != nil && aws.ToString(current.Token.RefreshToken) == aws.ToString(data.Token.RefreshToken) {
		if err := p.OIDCTokenCache.Remove(p.StartURL); err != nil && err != keyring.ErrKeyNotFound {
			return nil, false, err
		}
	}
	return nil, true, nil
}

// isOIDCRejection reports whether the OIDC service refused the refresh in a
// way that retrying cannot fix, so a new login is the only way forward. It
// covers the grant and client errors (a revoked or already redeemed refresh
// token, an ended session, an expired registration) as well as the request
// errors that would be answered the same way every time, such as scopes an
// administrator no longer allows.
//
// Everything else is transient and keeps the refresh token for the next
// attempt: transport failures, 5xx, and throttling in particular. Throttling
// is not distinguishable by status code alone (SlowDownException is a 400 and
// API-level throttling a 429), and it is most likely exactly when several
// credential_process callers refresh at once, which is the burst this change
// exists to keep out of the browser.
func isOIDCRejection(err error) bool {
	var (
		accessDenied         *ssooidctypes.AccessDeniedException
		expiredToken         *ssooidctypes.ExpiredTokenException
		invalidClient        *ssooidctypes.InvalidClientException
		invalidGrant         *ssooidctypes.InvalidGrantException
		invalidRequest       *ssooidctypes.InvalidRequestException
		invalidScope         *ssooidctypes.InvalidScopeException
		unauthorizedClient   *ssooidctypes.UnauthorizedClientException
		unsupportedGrantType *ssooidctypes.UnsupportedGrantTypeException
	)
	return errors.As(err, &accessDenied) ||
		errors.As(err, &expiredToken) ||
		errors.As(err, &invalidClient) ||
		errors.As(err, &invalidGrant) ||
		errors.As(err, &invalidRequest) ||
		errors.As(err, &invalidScope) ||
		errors.As(err, &unauthorizedClient) ||
		errors.As(err, &unsupportedGrantType)
}

// refreshOIDCToken exchanges the refresh token of an expired cached token for
// a new access token, using the client registration the token was issued to.
func (p *SSORoleCredentialsProvider) refreshOIDCToken(ctx context.Context, data *OIDCTokenData) (*OIDCTokenData, error) {
	t, err := p.OIDCClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     aws.String(data.ClientID),
		ClientSecret: aws.String(data.ClientSecret),
		GrantType:    aws.String("refresh_token"),
		RefreshToken: data.Token.RefreshToken,
	})
	if err != nil {
		return nil, err
	}
	if t.RefreshToken == nil {
		// Identity Center rotates the refresh token on every use; keep the
		// previous one if a server ever omits it rather than losing the ability
		// to refresh.
		t.RefreshToken = data.Token.RefreshToken
	}
	log.Printf("Refreshed OIDC access token for %s (expires in: %ds)", p.StartURL, t.ExpiresIn)

	return &OIDCTokenData{
		Token:                 *t,
		ClientID:              data.ClientID,
		ClientSecret:          data.ClientSecret,
		ClientSecretExpiresAt: data.ClientSecretExpiresAt,
	}, nil
}

// deviceCodeReason returns why to use the device code flow instead of PKCE, or
// "". PKCE needs the browser on this machine to reach the 127.0.0.1 callback.
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

func (p *SSORoleCredentialsProvider) newOIDCTokenDeviceCode(ctx context.Context) (*OIDCTokenData, error) {
	clientCreds, err := p.OIDCClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("aws-vault"),
		ClientType: aws.String("public"),
		Scopes:     p.RegistrationScopes,
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
			if err := p.sleepPoll(ctx, retryInterval); err != nil {
				return nil, err
			}
			continue
		}

		log.Printf("Created new OIDC access token for %s (expires in: %ds, refresh token: %t)", p.StartURL, t.ExpiresIn, t.RefreshToken != nil)
		return &OIDCTokenData{
			Token:                 *t,
			ClientID:              aws.ToString(clientCreds.ClientId),
			ClientSecret:          aws.ToString(clientCreds.ClientSecret),
			ClientSecretExpiresAt: time.Unix(clientCreds.ClientSecretExpiresAt, 0),
		}, nil
	}
}

// sleepPoll waits between device code polls. It goes through ssoSleep when
// the provider was built by the constructor, so a cancelled aws-vault stops
// polling instead of sitting out the interval, and falls back to pollSleep
// for providers assembled directly in tests.
func (p *SSORoleCredentialsProvider) sleepPoll(ctx context.Context, d time.Duration) error {
	if p.ssoSleep != nil {
		return p.ssoSleep(ctx, d)
	}
	pollSleep(d)
	return nil
}

// pkceSignInTimeout bounds the wait for the browser, as in the AWS CLI.
var pkceSignInTimeout = 10 * time.Minute

// newOIDCTokenPKCE generates a new OIDC token using the authorization code flow
// with PKCE (https://datatracker.ietf.org/doc/html/rfc7636).
func (p *SSORoleCredentialsProvider) newOIDCTokenPKCE(ctx context.Context) (*OIDCTokenData, error) {
	scopes := p.pkceScopes()

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
		Scopes:       scopes,
		IssuerUrl:    aws.String(p.StartURL),
		RedirectUris: []string{"http://127.0.0.1/oauth/callback"},
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Created new OIDC client (expires at: %s)", time.Unix(clientCreds.ClientSecretExpiresAt, 0))

	cbServer, err := newOauthCallbackServer(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create oauthCallbackServer: %w", err)
	}
	log.Printf("oauthCallbackServer callback endpoint: %s", cbServer.redirectURI())
	defer cbServer.shutdown() //nolint:contextcheck // must run even after ctx is cancelled
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
		"scopes":                {strings.Join(scopes, " ")},
	}
	authorizeURL, err := p.authorizeURL(ctx)
	if err != nil {
		return nil, err
	}
	authorizeURL.RawQuery = args.Encode()
	log.Printf("Authorize URL: %s", authorizeURL.String())

	p.openOrPrintURL(authorizeURL.String())

	var r oauthCallbackResult
	select {
	case r = <-cbServer.resultChan:
	case <-ctx.Done():
		return nil, fmt.Errorf("aborted waiting for OAuth callback: %w", ctx.Err())
	case <-time.After(pkceSignInTimeout):
		return nil, fmt.Errorf("SSO sign-in did not complete in the browser within %s", pkceSignInTimeout)
	}

	if r.err != nil {
		return nil, r.err
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

	log.Printf("Created new OIDC access token for %s (expires in: %ds, refresh token: %t)", p.StartURL, tok.ExpiresIn, tok.RefreshToken != nil)
	return &OIDCTokenData{
		Token:                 *tok,
		ClientID:              aws.ToString(clientCreds.ClientId),
		ClientSecret:          aws.ToString(clientCreds.ClientSecret),
		ClientSecretExpiresAt: time.Unix(clientCreds.ClientSecretExpiresAt, 0),
	}, nil
}

// pkceDefaultScope is requested when sso_registration_scopes is unset, as in
// the AWS CLI: the authorization code grant needs a scope.
const pkceDefaultScope = "sso:account:access"

// pkceScopes returns the configured registration scopes, or pkceDefaultScope.
func (p *SSORoleCredentialsProvider) pkceScopes() []string {
	if len(p.RegistrationScopes) > 0 {
		return p.RegistrationScopes
	}
	return []string{pkceDefaultScope}
}

// authorizeURL derives the /authorize endpoint, which isn't a modeled operation,
// from the client's resolved endpoint, as the AWS CLI does, so every partition works.
func (p *SSORoleCredentialsProvider) authorizeURL(ctx context.Context) (*url.URL, error) {
	o := p.OIDCClient.Options()
	e, err := o.EndpointResolverV2.ResolveEndpoint(ctx, ssooidc.EndpointParameters{
		Region:   aws.String(o.Region),
		Endpoint: o.BaseEndpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve the OIDC endpoint: %w", err)
	}
	if e.URI.Scheme == "" || e.URI.Host == "" {
		return nil, fmt.Errorf("OIDC endpoint %q is not an absolute URL", e.URI.String())
	}
	// JoinPath keeps any path prefix of a custom endpoint
	return e.URI.JoinPath("authorize"), nil
}

// openBrowser is a variable so tests can replace it.
var openBrowser = OpenBrowser

// OpenBrowser opens url in browser, or in the default browser if browser is "".
// A named browser is started without waiting: launchers such as google-chrome
// only return once a newly started browser exits.
func OpenBrowser(url, browser string) error {
	if browser == "" {
		return open.Run(url)
	}
	return open.StartWith(url, browser)
}

// openOrPrintURL opens url in the browser, or only prints it if UseStdout is set.
func (p *SSORoleCredentialsProvider) openOrPrintURL(url string) {
	if p.UseStdout {
		fmt.Fprintf(os.Stderr, "Open the SSO authorization page in a browser (use Ctrl-C to abort)\n%s\n", url)
	} else {
		browser := p.Browser
		if browser == "" {
			browser = "your default browser"
		}
		fmt.Fprintf(os.Stderr, "Opening the SSO authorization page in %s (use Ctrl-C to abort)\n%s\n", browser, url)
		log.Println("Opening SSO authorization page in browser")
		if err := openBrowser(url, p.Browser); err != nil {
			log.Printf("Failed to open browser: %s", err)
		}
	}
}

// newOauthCallbackServer binds a random loopback port for the OAuth2 callback,
// which reports the authorization code on resultChan.
func newOauthCallbackServer(ctx context.Context) (*oauthCallbackServer, error) {
	// loopback only: the callback carries the authorization code
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
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
		writeCallbackPage(w, callbackView{
			Title:   "Sign-in failed",
			Message: fmt.Sprintf("The request was not approved (%s). See your terminal for details.", errCode),
		})
		s.report(oauthCallbackResult{err: fmt.Errorf("authorization error: %s: %s", errCode, errDesc)})
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeCallbackPage(w, callbackView{
			Title:   "Sign-in failed",
			Message: "No authorization code was received. See your terminal for details.",
		})
		s.report(oauthCallbackResult{err: errors.New("no authorization code received")})
		return
	}
	writeCallbackPage(w, callbackView{
		OK:      true,
		Title:   "Request approved",
		Message: "You have approved the request for access. aws-vault will finish signing in.",
	})
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
var callbackPage = template.Must(template.New("callback").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>aws-vault | {{.Title}}</title>
{{if .OK}}<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><circle cx='8' cy='8' r='8' fill='%231a7f37'/><path d='m4.6 8.2 2.3 2.3 4.5-4.6' fill='none' stroke='white' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/></svg>">
{{- else}}<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><circle cx='8' cy='8' r='8' fill='%23cf222e'/><path d='m5.4 5.4 5.2 5.2m0-5.2-5.2 5.2' fill='none' stroke='white' stroke-width='1.8' stroke-linecap='round'/></svg>">
{{- end}}
<style>
:root { color-scheme: light dark; --fg: #16191f; --bg: #fff;
  --ok: #1a7f37; --ok-bg: #effbf1; --err: #cf222e; --err-bg: #fff1f0; }
@media (prefers-color-scheme: dark) { :root { --fg: #e6e9ee; --bg: #16191f;
  --ok: #3fb950; --ok-bg: #12261a; --err: #f85149; --err-bg: #2d1416; } }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg);
  color: var(--fg); font: 15px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { width: min(400px, calc(100vw - 32px)); }
.card { display: flex; gap: 10px; padding: 14px 16px; border: 2px solid var(--c); border-radius: 12px;
  background: var(--c-bg); }
.ok { --c: var(--ok); --c-bg: var(--ok-bg); }
.err { --c: var(--err); --c-bg: var(--err-bg); }
svg { flex: none; width: 20px; height: 20px; margin-top: 1px; color: var(--c); }
h1 { margin: 0; font-size: 15px; }
p { margin: 0; }
.hint { margin-top: 20px; }
</style></head>
<body><main>
<div class="card {{if .OK}}ok{{else}}err{{end}}">
<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="10" cy="10" r="8.5"/>{{if .OK}}<path d="m6 10.3 2.7 2.7L14.2 7.3"/>{{else}}<path d="m7.2 7.2 5.6 5.6m0-5.6-5.6 5.6"/>{{end}}</svg>
<div><h1>{{.Title}}</h1><p>{{.Message}}</p></div>
</div>
<p class="hint">You can close this window.</p>
</main>
<script>history.replaceState(null, "", location.pathname); window.close()</script>
</body></html>
`))

type callbackView struct {
	OK             bool
	Title, Message string
}

func writeCallbackPage(w http.ResponseWriter, v callbackView) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	// the callback URL carries the authorization code
	h.Set("Referrer-Policy", "no-referrer")
	if err := callbackPage.Execute(w, v); err != nil {
		log.Printf("Failed to write the OAuth callback page: %s", err)
	}
}

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
	state      string
	resultChan chan oauthCallbackResult
}

func (s *oauthCallbackServer) Serve() error {
	return s.h.Serve(s.ln)
}

// shutdown lets an in-flight callback finish sending its page before closing.
func (s *oauthCallbackServer) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.h.Shutdown(ctx); err != nil {
		log.Printf("Failed to shut down oauthCallbackServer: %s", err)
		_ = s.h.Close()
	}
}

func retryAfterFromError(err error) (time.Duration, bool) {
	var rspError *awshttp.ResponseError
	if errors.As(err, &rspError) {
		if rspError.Response != nil {
			if d, ok := parseRetryAfter(rspError.Response.Header.Get("Retry-After")); ok {
				return d, true
			}
		}
	}
	return 0, false
}

func parseRetryAfter(value string) (time.Duration, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(trimmed); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(trimmed); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

func isSSORateLimitError(err error) bool {
	var tooMany *ssotypes.TooManyRequestsException
	if errors.As(err, &tooMany) {
		return true
	}
	var rspError *awshttp.ResponseError
	if errors.As(err, &rspError) && rspError.HTTPStatusCode() == http.StatusTooManyRequests {
		return true
	}
	return false
}

func jitterRetryAfter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	d := jitterDelay(base)
	// Never retry sooner than the server requested.
	if d < base {
		d = base
	}
	return d
}

func jitteredBackoff(base, maxDelay time.Duration, attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	capDelay := base << uint(attempt-1)
	if maxDelay < capDelay {
		capDelay = maxDelay
	}
	if capDelay < base {
		// Overflow: large shift wrapped negative; clamp to maxDelay, not base,
		// so late retries stay backed off instead of becoming aggressive.
		capDelay = maxDelay
	}
	return jitterDelay(capDelay)
}

func jitterDelay(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	lo := ssoRetryAfterJitterMin
	hi := ssoRetryAfterJitterMax
	if hi < lo {
		hi = lo
	}
	factor := lo + rand.Float64()*(hi-lo)
	return time.Duration(float64(base) * factor)
}
