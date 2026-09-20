package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/byteness/keyring"
)

type OIDCTokenKeyring struct {
	Keyring keyring.Keyring
}

// OIDCTokenData is a cached OIDC token together with the OIDC client
// registration it was issued to. The client credentials are what allow an
// expired access token to be exchanged for a new one using its refresh token.
type OIDCTokenData struct {
	Token      ssooidc.CreateTokenOutput
	Expiration time.Time

	// ClientID and ClientSecret identify the OIDC client returned by
	// RegisterClient. Entries written by earlier versions of aws-vault do not
	// have them, which simply makes those entries non-refreshable.
	ClientID              string    `json:",omitempty"`
	ClientSecret          string    `json:",omitempty"`
	ClientSecretExpiresAt time.Time `json:",omitzero"`
}

// Expired reports whether the access token has reached its expiration.
func (d *OIDCTokenData) Expired() bool {
	return !time.Now().Before(d.Expiration)
}

// Refreshable reports whether the entry carries everything needed to redeem
// its refresh token: the refresh token itself and a client registration that
// has not expired.
func (d *OIDCTokenData) Refreshable() bool {
	if d.ClientID == "" || d.ClientSecret == "" || aws.ToString(d.Token.RefreshToken) == "" {
		return false
	}
	return d.ClientSecretExpiresAt.IsZero() || time.Now().Before(d.ClientSecretExpiresAt)
}

const oidcTokenKeyPrefix = "oidc:"

func (o *OIDCTokenKeyring) fmtKey(startURL string) string {
	return oidcTokenKeyPrefix + startURL
}

func IsOIDCTokenKey(k string) bool {
	return strings.HasPrefix(k, oidcTokenKeyPrefix)
}

func (o OIDCTokenKeyring) Has(startURL string) (bool, error) {
	keys, err := o.Keys()
	if err != nil {
		return false, err
	}

	for _, k := range keys {
		if startURL == k {
			return true, nil
		}
	}

	return false, nil
}

// Get returns the cached token for startURL. An expired token is removed and
// reported as keyring.ErrKeyNotFound, unless it is Refreshable(): then it is
// returned with Token.ExpiresIn set to 0 so the caller can redeem the refresh
// token. Callers must check Expired() before using Token.AccessToken.
func (o OIDCTokenKeyring) Get(startURL string) (*OIDCTokenData, error) {
	item, err := o.Keyring.Get(o.fmtKey(startURL))
	if err != nil {
		return nil, err
	}

	val := OIDCTokenData{}

	if err = json.Unmarshal(item.Data, &val); err != nil {
		log.Printf("Invalid data in keyring: %s", err.Error())
		return nil, keyring.ErrKeyNotFound
	}
	if val.Expired() {
		if !val.Refreshable() {
			log.Printf("OIDC token for '%s' expired, removing", startURL)
			_ = o.Remove(startURL)
			return nil, keyring.ErrKeyNotFound
		}
		log.Printf("OIDC token for '%s' expired, but has a refresh token", startURL)
		val.Token.ExpiresIn = 0
		return &val, nil
	}

	val.Token.ExpiresIn = int32(time.Until(val.Expiration) / time.Second)

	return &val, nil
}

// Set stores the token for startURL, computing its expiration from
// Token.ExpiresIn relative to now.
func (o OIDCTokenKeyring) Set(startURL string, data *OIDCTokenData) error {
	val := *data
	val.Expiration = time.Now().Add(time.Duration(val.Token.ExpiresIn) * time.Second)

	valJSON, err := json.Marshal(val)
	if err != nil {
		return err
	}

	// Like sessions, the OIDC token is a cache and trusts aws-vault to read it
	// back without a keychain authorization prompt. See SessionKeyring.Set.
	return o.Keyring.Set(keyring.Item{
		Key:         o.fmtKey(startURL),
		Data:        valJSON,
		Label:       fmt.Sprintf("aws-vault oidc token for %s (expires %s)", startURL, val.Expiration.Format(time.RFC3339)),
		Description: "aws-vault oidc token",
	})
}

func (o OIDCTokenKeyring) Remove(startURL string) error {
	return o.Keyring.Remove(o.fmtKey(startURL))
}

func (o *OIDCTokenKeyring) RemoveAll() (n int, err error) {
	allKeys, err := o.Keys()
	if err != nil {
		return 0, err
	}
	for _, key := range allKeys {
		if err = o.Remove(key); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (o *OIDCTokenKeyring) Keys() (kk []string, err error) {
	allKeys, err := o.Keyring.Keys()
	if err != nil {
		return nil, err
	}

	for _, k := range allKeys {
		if IsOIDCTokenKey(k) {
			kk = append(kk, strings.TrimPrefix(k, oidcTokenKeyPrefix))
		}
	}

	return kk, nil
}
