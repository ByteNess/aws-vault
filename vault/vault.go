package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/keyring"
)

var defaultExpirationWindow = 5 * time.Minute

func init() {
	if d, err := time.ParseDuration(os.Getenv("AWS_MIN_TTL")); err == nil {
		defaultExpirationWindow = d
	}
}

func NewAwsConfig(region, stsRegionalEndpoints, endpointURL string) aws.Config {
	return aws.Config{
		Region:                      region,
		EndpointResolverWithOptions: getSTSEndpointResolver(stsRegionalEndpoints, endpointURL),
	}
}

func NewAwsConfigWithCredsProvider(credsProvider aws.CredentialsProvider, region, stsRegionalEndpoints, endpointURL string) aws.Config {
	return aws.Config{
		Region:                      region,
		Credentials:                 credsProvider,
		EndpointResolverWithOptions: getSTSEndpointResolver(stsRegionalEndpoints, endpointURL),
	}
}

func FormatKeyForDisplay(k string) string {
	return fmt.Sprintf("****************%s", k[len(k)-4:])
}

func isMasterCredentialsProvider(credsProvider aws.CredentialsProvider) bool {
	_, ok := credsProvider.(*KeyringProvider)
	return ok
}

// NewMasterCredentialsProvider creates a provider for the master credentials
func NewMasterCredentialsProvider(k *CredentialKeyring, credentialsName string) *KeyringProvider {
	return &KeyringProvider{k, credentialsName}
}

func NewSessionTokenProvider(credsProvider aws.CredentialsProvider, k keyring.Keyring, config *ProfileConfig, useSessionCache bool) (aws.CredentialsProvider, error) {
	cfg := NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints, config.EndpointURL)

	sessionTokenProvider := &SessionTokenProvider{
		StsClient: sts.NewFromConfig(cfg),
		Duration:  config.GetSessionTokenDuration(),
		Mfa:       NewMfa(config),
	}

	if useSessionCache {
		return &CachedSessionProvider{
			SessionKey: SessionMetadata{
				Type:        "sts.GetSessionToken",
				ProfileName: config.ProfileName,
				MfaSerial:   config.MfaSerial,
			},
			Keyring:         &SessionKeyring{Keyring: k},
			ExpiryWindow:    defaultExpirationWindow,
			SessionProvider: sessionTokenProvider,
		}, nil
	}

	return sessionTokenProvider, nil
}

// NewAssumeRoleProvider returns a provider that generates credentials using AssumeRole
func NewAssumeRoleProvider(credsProvider aws.CredentialsProvider, k keyring.Keyring, config *ProfileConfig, useSessionCache bool) (aws.CredentialsProvider, error) {
	cfg := NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints, config.EndpointURL)

	p := &AssumeRoleProvider{
		StsClient:         sts.NewFromConfig(cfg),
		RoleARN:           config.RoleARN,
		RoleSessionName:   config.RoleSessionName,
		ExternalID:        config.ExternalID,
		Duration:          config.AssumeRoleDuration,
		Tags:              config.SessionTags,
		TransitiveTagKeys: config.TransitiveSessionTags,
		SourceIdentity:    config.SourceIdentity,
		Mfa:               NewMfa(config),
	}

	if useSessionCache && config.MfaSerial != "" {
		return &CachedSessionProvider{
			SessionKey: SessionMetadata{
				Type:        "sts.AssumeRole",
				ProfileName: config.ProfileName,
				MfaSerial:   config.MfaSerial,
			},
			Keyring:         &SessionKeyring{Keyring: k},
			ExpiryWindow:    defaultExpirationWindow,
			SessionProvider: p,
		}, nil
	}

	return p, nil
}

// NewAssumeRoleWithWebIdentityProvider returns a provider that generates
// credentials using AssumeRoleWithWebIdentity
func NewAssumeRoleWithWebIdentityProvider(k keyring.Keyring, config *ProfileConfig, useSessionCache bool) (aws.CredentialsProvider, error) {
	cfg := NewAwsConfig(config.Region, config.STSRegionalEndpoints, config.EndpointURL)

	p := &AssumeRoleWithWebIdentityProvider{
		StsClient:               sts.NewFromConfig(cfg),
		RoleARN:                 config.RoleARN,
		RoleSessionName:         config.RoleSessionName,
		WebIdentityTokenFile:    config.WebIdentityTokenFile,
		WebIdentityTokenProcess: config.WebIdentityTokenProcess,
		Duration:                config.AssumeRoleDuration,
	}

	if useSessionCache {
		return &CachedSessionProvider{
			SessionKey: SessionMetadata{
				Type:        "sts.AssumeRoleWithWebIdentity",
				ProfileName: config.ProfileName,
			},
			Keyring:         &SessionKeyring{Keyring: k},
			ExpiryWindow:    defaultExpirationWindow,
			SessionProvider: p,
		}, nil
	}

	return p, nil
}

// NewSSORoleCredentialsProvider creates a provider for SSO credentials
func NewSSORoleCredentialsProvider(k keyring.Keyring, config *ProfileConfig, useSessionCache bool) (aws.CredentialsProvider, error) {
	cfg := NewAwsConfig(config.SSORegion, config.STSRegionalEndpoints, config.EndpointURL)

	ssoRoleCredentialsProvider := &SSORoleCredentialsProvider{
		OIDCClient: ssooidc.NewFromConfig(cfg),
		StartURL:   config.SSOStartURL,
		SSOClient:  sso.NewFromConfig(cfg),
		AccountID:  config.SSOAccountID,
		RoleName:   config.SSORoleName,
		UseStdout:  config.SSOUseStdout,
	}

	if useSessionCache {
		ssoRoleCredentialsProvider.OIDCTokenCache = OIDCTokenKeyring{Keyring: k}
		return &CachedSessionProvider{
			SessionKey: SessionMetadata{
				Type:        "sso.GetRoleCredentials",
				ProfileName: config.ProfileName,
				MfaSerial:   config.SSOStartURL,
			},
			Keyring:         &SessionKeyring{Keyring: k},
			ExpiryWindow:    defaultExpirationWindow,
			SessionProvider: ssoRoleCredentialsProvider,
		}, nil
	}

	return ssoRoleCredentialsProvider, nil
}

// ssoTokenCacheKey returns the key used to compute the standard SSO cache file path.
// For profiles using [sso-session] this is the session name; for legacy profiles it is the start URL.
func ssoTokenCacheKey(config *ProfileConfig) string {
	if config.SSOSession != "" {
		return config.SSOSession
	}
	return config.SSOStartURL
}

// SyncOIDCTokenToStandardCache writes the OIDC access token for the given profile
// from the keyring to the standard AWS SSO cache file (~/.aws/sso/cache/<sha1>.json),
// so that other AWS tools that read the standard file location can use it.
func SyncOIDCTokenToStandardCache(config *ProfileConfig, k keyring.Keyring) error {
	tokenFilepath, err := ssocreds.StandardCachedTokenFilepath(ssoTokenCacheKey(config))
	if err != nil {
		return err
	}

	token, err := (OIDCTokenKeyring{Keyring: k}).Get(config.SSOStartURL)
	if err != nil {
		return fmt.Errorf("OIDC token not found in keyring for %s: %w", config.SSOStartURL, err)
	}

	// ExpiresIn is recalculated by OIDCTokenKeyring.Get() to reflect the
	// remaining seconds until expiry, so time.Now().Add() is correct here.
	expiration := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	type cachedToken struct {
		AccessToken  string `json:"accessToken"`
		ExpiresAt    string `json:"expiresAt"`
		RefreshToken string `json:"refreshToken,omitempty"`
	}

	t := cachedToken{
		AccessToken: aws.ToString(token.AccessToken),
		ExpiresAt:   expiration.UTC().Format(time.RFC3339),
	}
	if token.RefreshToken != nil {
		t.RefreshToken = aws.ToString(token.RefreshToken)
	}

	b, err := json.Marshal(t)
	if err != nil {
		return err
	}

	// MkdirAll only sets perms when creating the directory. If
	// ~/.aws/sso/cache already exists with looser permissions (e.g. 0755
	// from a prior AWS CLI run), we intentionally do not tighten them here
	// — changing directory perms out from under another tool would be
	// surprising. The token file itself is written 0600 below.
	if err := os.MkdirAll(filepath.Dir(tokenFilepath), 0700); err != nil {
		return err
	}

	return writeFileAtomic(tokenFilepath, b, 0600)
}

// writeFileAtomic writes data to filename atomically by first writing to a
// temporary file in the same directory and then renaming it into place.
// The temp file is created with mode 0600 and fsync'd before the rename so
// that a crash or concurrent writer cannot leave a partial or corrupt file
// at the destination — readers either see the old contents or the new,
// never a half-written mix.
//
// The temp file is created in the same directory as filename to guarantee
// that os.Rename is atomic (rename(2) is only atomic within a single
// filesystem; /tmp is often on a different one).
//
// Note: this does not tighten permissions on an existing parent directory.
// Callers that need 0700 on the directory must enforce that separately,
// and should be aware that os.MkdirAll is a no-op (including on perms) if
// the directory already exists.
func writeFileAtomic(filename string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(filename)

	f, err := os.CreateTemp(dir, filepath.Base(filename)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := f.Name()

	// Best-effort cleanup if we bail out before the rename succeeds.
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	// CreateTemp defaults to 0600 on Unix, but be explicit — umask and
	// platform behavior vary, and this file holds a bearer token.
	if err = f.Chmod(perm); err != nil {
		f.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}

	if _, err = f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}

	// fsync before rename so the contents are durable on disk before any
	// reader can observe the new inode at the target path.
	if err = f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}

	if err = f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err = os.Rename(tmpName, filename); err != nil {
		return fmt.Errorf("rename temp file into place: %w", err)
	}

	return nil
}

// NewCredentialProcessProvider creates a provider to retrieve credentials from an external
// executable as described in https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
func NewCredentialProcessProvider(k keyring.Keyring, config *ProfileConfig, useSessionCache bool) (aws.CredentialsProvider, error) {
	credentialProcessProvider := &CredentialProcessProvider{
		CredentialProcess: config.CredentialProcess,
	}

	if useSessionCache {
		return &CachedSessionProvider{
			SessionKey: SessionMetadata{
				Type:        "credential_process",
				ProfileName: config.ProfileName,
			},
			Keyring:         &SessionKeyring{Keyring: k},
			ExpiryWindow:    defaultExpirationWindow,
			SessionProvider: credentialProcessProvider,
		}, nil
	}

	return credentialProcessProvider, nil
}

func NewFederationTokenProvider(ctx context.Context, credsProvider aws.CredentialsProvider, config *ProfileConfig) (*FederationTokenProvider, error) {
	cfg := NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints, config.EndpointURL)

	name, err := GetUsernameFromSession(ctx, cfg)
	if err != nil {
		return nil, err
	}

	log.Printf("Using GetFederationToken for credentials")
	return &FederationTokenProvider{
		StsClient: sts.NewFromConfig(cfg),
		Name:      name,
		Duration:  config.GetFederationTokenDuration,
	}, nil
}

func FindMasterCredentialsNameFor(profileName string, keyring *CredentialKeyring, config *ProfileConfig) (string, error) {
	hasMasterCreds, err := keyring.Has(profileName)
	if err != nil {
		return "", err
	}

	if hasMasterCreds {
		return profileName, nil
	}

	if profileName == config.SourceProfileName {
		return "", fmt.Errorf("No master credentials found")
	}

	return FindMasterCredentialsNameFor(config.SourceProfileName, keyring, config)
}

type TempCredentialsCreator struct {
	Keyring *CredentialKeyring
	// DisableSessions will disable the use of GetSessionToken
	DisableSessions bool
	// DisableCache will disable the use of the session cache
	DisableCache bool
	// DisableSessionsForProfile is a profile for which sessions should not be used
	DisableSessionsForProfile string

	chainedMfa string
}

func (t *TempCredentialsCreator) getSourceCreds(config *ProfileConfig, hasStoredCredentials bool) (sourcecredsProvider aws.CredentialsProvider, err error) {
	if hasStoredCredentials {
		log.Printf("profile %s: using stored credentials", config.ProfileName)
		return NewMasterCredentialsProvider(t.Keyring, config.ProfileName), nil
	}

	if config.HasSourceProfile() {
		log.Printf("profile %s: sourcing credentials from profile %s", config.ProfileName, config.SourceProfile.ProfileName)
		return t.GetProviderForProfile(config.SourceProfile)
	}

	return nil, fmt.Errorf("profile %s: credentials missing", config.ProfileName)
}

func (t *TempCredentialsCreator) primeWithGetSessionToken(config *ProfileConfig, sourcecredsProvider aws.CredentialsProvider) (aws.CredentialsProvider, bool, error) {
	isSourceForRoleProfile := config.ChainedFromProfile != nil && config.ChainedFromProfile.HasRole()
	shouldPrime := !config.HasRole() || isSourceForRoleProfile
	if !shouldPrime || !isMasterCredentialsProvider(sourcecredsProvider) {
		return sourcecredsProvider, true, nil
	}

	canUseGetSessionToken, reason := t.canUseGetSessionToken(config)
	if !canUseGetSessionToken {
		log.Printf("profile %s: skipping GetSessionToken because %s", config.ProfileName, reason)
		return sourcecredsProvider, config.HasRole(), nil
	}

	t.chainedMfa = config.MfaSerial
	log.Printf("profile %s: using GetSessionToken %s", config.ProfileName, mfaDetails(false, config))
	sourcecredsProvider, err := NewSessionTokenProvider(sourcecredsProvider, t.Keyring.Keyring, config, !t.DisableCache)
	if err != nil {
		return sourcecredsProvider, false, err
	}

	return sourcecredsProvider, config.HasRole(), nil
}

func requiresRoleChainingDurationCap(credsProvider aws.CredentialsProvider) bool {
	switch p := credsProvider.(type) {
	case *SessionTokenProvider, *AssumeRoleProvider:
		return true
	case *CachedSessionProvider:
		return requiresRoleChainingDurationCap(p.SessionProvider)
	default:
		return false
	}
}

func capAssumeRoleDurationIfChained(sourcecredsProvider aws.CredentialsProvider, config *ProfileConfig) {
	if !requiresRoleChainingDurationCap(sourcecredsProvider) || config.AssumeRoleDuration <= RoleChainingMaximumDuration {
		return
	}

	log.Printf(
		"profile %s: capping AssumeRole duration from %s to AWS maximum %s for role chaining",
		config.ProfileName,
		config.AssumeRoleDuration,
		RoleChainingMaximumDuration,
	)
	config.AssumeRoleDuration = RoleChainingMaximumDuration
}

func (t *TempCredentialsCreator) getSourceCredWithSession(config *ProfileConfig, hasStoredCredentials bool) (sourcecredsProvider aws.CredentialsProvider, err error) {
	sourcecredsProvider, err = t.getSourceCreds(config, hasStoredCredentials)
	if err != nil {
		return nil, err
	}

	sourcecredsProvider, shouldAssumeRole, err := t.primeWithGetSessionToken(config, sourcecredsProvider)
	if err != nil {
		return sourcecredsProvider, err
	}
	if !shouldAssumeRole {
		return sourcecredsProvider, nil
	}

	if !config.HasRole() {
		return sourcecredsProvider, nil
	}

	capAssumeRoleDurationIfChained(sourcecredsProvider, config)

	isMfaChained := config.MfaSerial != "" && config.MfaSerial == t.chainedMfa
	if isMfaChained {
		config.MfaSerial = ""
	}
	log.Printf("profile %s: using AssumeRole %s", config.ProfileName, mfaDetails(isMfaChained, config))
	return NewAssumeRoleProvider(sourcecredsProvider, t.Keyring.Keyring, config, !t.DisableCache)
}

func (t *TempCredentialsCreator) GetProviderForProfile(config *ProfileConfig) (aws.CredentialsProvider, error) {
	hasStoredCredentials, err := t.Keyring.Has(config.ProfileName)
	if err != nil {
		return nil, err
	}

	if hasStoredCredentials || config.HasSourceProfile() {
		return t.getSourceCredWithSession(config, hasStoredCredentials)
	}

	if config.HasSSOStartURL() {
		log.Printf("profile %s: using SSO role credentials", config.ProfileName)
		return NewSSORoleCredentialsProvider(t.Keyring.Keyring, config, !t.DisableCache)
	}

	if config.HasWebIdentity() {
		log.Printf("profile %s: using web identity", config.ProfileName)
		return NewAssumeRoleWithWebIdentityProvider(t.Keyring.Keyring, config, !t.DisableCache)
	}

	if config.HasCredentialProcess() {
		log.Printf("profile %s: using credential process", config.ProfileName)
		return NewCredentialProcessProvider(t.Keyring.Keyring, config, !t.DisableCache)
	}

	return nil, fmt.Errorf("profile %s: credentials missing", config.ProfileName)
}

// canUseGetSessionToken determines if GetSessionToken should be used, and if not returns a reason
func (t *TempCredentialsCreator) canUseGetSessionToken(c *ProfileConfig) (bool, string) {
	if t.DisableSessions {
		return false, "sessions are disabled"
	}
	if t.DisableSessionsForProfile == c.ProfileName {
		return false, "sessions are disabled for this profile"
	}

	if c.IsChained() {
		if !c.ChainedFromProfile.HasMfaSerial() {
			return false, fmt.Sprintf("profile '%s' has no MFA serial defined", c.ChainedFromProfile.ProfileName)
		}

		if !c.HasMfaSerial() && c.ChainedFromProfile.HasMfaSerial() {
			return false, fmt.Sprintf("profile '%s' has no MFA serial defined", c.ProfileName)
		}

		if c.ChainedFromProfile.MfaSerial != c.MfaSerial {
			return false, fmt.Sprintf("MFA serial doesn't match profile '%s'", c.ChainedFromProfile.ProfileName)
		}

	}

	return true, ""
}

func mfaDetails(mfaChained bool, config *ProfileConfig) string {
	if mfaChained {
		return "(chained MFA)"
	}
	if config.HasMfaSerial() {
		return "(with MFA)"
	}
	return ""
}

// NewTempCredentialsProvider creates a credential provider for the given config
func NewTempCredentialsProvider(config *ProfileConfig, keyring *CredentialKeyring, disableSessions bool, disableCache bool) (aws.CredentialsProvider, error) {
	t := TempCredentialsCreator{
		Keyring:         keyring,
		DisableSessions: disableSessions,
		DisableCache:    disableCache,
	}
	return t.GetProviderForProfile(config)
}
