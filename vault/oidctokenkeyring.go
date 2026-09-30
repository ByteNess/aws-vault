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

// OIDCTokenKeyring stores OIDC access tokens in the keyring, by SSO start URL.
type OIDCTokenKeyring struct {
	Keyring keyring.Keyring
}

// OIDCTokenData is the stored form of an OIDC token, with its expiry time.
type OIDCTokenData struct {
	Token      ssooidc.CreateTokenOutput
	Expiration time.Time
	// Client is the registration the token was issued to. Refreshing the token
	// needs it; tokens stored by earlier versions don't have it.
	Client *OIDCClient `json:",omitempty"`
}

// OIDCClient is an OIDC client registration.
type OIDCClient struct {
	ID        string
	Secret    string
	ExpiresAt time.Time
}

// refreshable reports whether the token can be refreshed without signing in again.
func (d *OIDCTokenData) refreshable() bool {
	return d.Client != nil && aws.ToString(d.Token.RefreshToken) != "" && time.Now().Before(d.Client.ExpiresAt)
}

const oidcTokenKeyPrefix = "oidc:"

func (o *OIDCTokenKeyring) fmtKey(startURL string) string {
	return oidcTokenKeyPrefix + startURL
}

// IsOIDCTokenKey reports whether keyring key k holds an OIDC token.
func IsOIDCTokenKey(k string) bool {
	return strings.HasPrefix(k, oidcTokenKeyPrefix)
}

// Has reports whether a token is stored for startURL.
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

// Get returns the unexpired token for startURL.
func (o OIDCTokenKeyring) Get(startURL string) (*ssooidc.CreateTokenOutput, error) {
	d, err := o.GetData(startURL)
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(d.Expiration) {
		return nil, keyring.ErrKeyNotFound
	}
	return &d.Token, nil
}

// GetData returns the stored token for startURL, which may have expired if it
// can be refreshed. A token that is neither is removed and reported as not found.
func (o OIDCTokenKeyring) GetData(startURL string) (*OIDCTokenData, error) {
	item, err := o.Keyring.Get(o.fmtKey(startURL))
	if err != nil {
		return nil, err
	}

	val := OIDCTokenData{}

	if err = json.Unmarshal(item.Data, &val); err != nil {
		log.Printf("Invalid data in keyring: %s", err.Error())
		return nil, keyring.ErrKeyNotFound
	}
	if time.Now().After(val.Expiration) && !val.refreshable() {
		log.Printf("OIDC token for '%s' expired, removing", startURL)
		_ = o.Remove(startURL)
		return nil, keyring.ErrKeyNotFound
	}

	val.Token.ExpiresIn = int32(max(time.Until(val.Expiration)/time.Second, 0))

	return &val, nil
}

// Set stores token for startURL.
func (o OIDCTokenKeyring) Set(startURL string, token *ssooidc.CreateTokenOutput) error {
	return o.SetData(startURL, token, nil)
}

// SetData stores token for startURL, with the client registration it was issued to.
func (o OIDCTokenKeyring) SetData(startURL string, token *ssooidc.CreateTokenOutput, client *OIDCClient) error {
	val := OIDCTokenData{
		Token:      *token,
		Expiration: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		Client:     client,
	}

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

// Remove deletes the token for startURL.
func (o OIDCTokenKeyring) Remove(startURL string) error {
	return o.Keyring.Remove(o.fmtKey(startURL))
}

// RemoveAll deletes all stored tokens and returns how many it deleted.
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

// Keys returns the start URLs that have a stored token.
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
