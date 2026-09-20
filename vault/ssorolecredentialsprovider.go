package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	// RegistrationScopes are the OAuth scopes requested when registering the
	// OIDC client (sso_registration_scopes). With scopes such as
	// sso:account:access, IAM Identity Center returns a refresh token alongside
	// the access token, so an expired token is renewed without a browser until
	// the Identity Center session itself ends.
	RegistrationScopes []string
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

// oidcRefreshWindow is how long before expiry a refreshable token is renewed.
// It matches the AWS CLI's SSOTokenProvider and keeps GetRoleCredentials from
// being handed a token with seconds left, whose 401 would drop the cached
// entry (refresh token included) and force a browser login.
const oidcRefreshWindow = 15 * time.Minute

func (p *SSORoleCredentialsProvider) getOIDCToken(ctx context.Context) (token *ssooidc.CreateTokenOutput, cached bool, err error) {
	if p.OIDCTokenCache != nil {
		data, err := p.OIDCTokenCache.Get(p.StartURL)
		if err != nil && err != keyring.ErrKeyNotFound {
			return nil, false, err
		}
		if data != nil {
			token, needLogin, err := p.cachedOIDCToken(ctx, data)
			if err != nil {
				return nil, false, err
			}
			if !needLogin {
				return token, true, nil
			}
		}
	}
	data, err := p.newOIDCToken(ctx)
	if err != nil {
		return nil, false, err
	}

	if p.OIDCTokenCache != nil {
		err = p.OIDCTokenCache.Set(p.StartURL, data)
		if err != nil {
			return nil, false, err
		}
	}
	return &data.Token, false, nil
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

// isOIDCRejection reports whether the OIDC service definitively refused the
// request (a 4xx such as InvalidGrantException or ExpiredTokenException), as
// opposed to a transport failure or a 5xx that may succeed on retry.
func isOIDCRejection(err error) bool {
	var rspError *awshttp.ResponseError
	if !errors.As(err, &rspError) {
		return false
	}
	code := rspError.HTTPStatusCode()
	return code >= 400 && code < 500
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

func (p *SSORoleCredentialsProvider) newOIDCToken(ctx context.Context) (*OIDCTokenData, error) {
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

	if p.UseStdout {
		fmt.Fprintf(os.Stderr, "Open the SSO authorization page in a browser (use Ctrl-C to abort)\n%s\n", aws.ToString(deviceCreds.VerificationUriComplete))
	} else {
		log.Println("Opening SSO authorization page in browser")
		fmt.Fprintf(os.Stderr, "Opening the SSO authorization page in your default browser (use Ctrl-C to abort)\n%s\n", aws.ToString(deviceCreds.VerificationUriComplete))
		if err := open.Run(aws.ToString(deviceCreds.VerificationUriComplete)); err != nil {
			log.Printf("Failed to open browser: %s", err)
		}
	}

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

		log.Printf("Created new OIDC access token for %s (expires in: %ds, refresh token: %t)", p.StartURL, t.ExpiresIn, t.RefreshToken != nil)
		return &OIDCTokenData{
			Token:                 *t,
			ClientID:              aws.ToString(clientCreds.ClientId),
			ClientSecret:          aws.ToString(clientCreds.ClientSecret),
			ClientSecretExpiresAt: time.Unix(clientCreds.ClientSecretExpiresAt, 0),
		}, nil
	}
}
