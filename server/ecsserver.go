// Package server serves credentials locally over the EC2 instance metadata and
// ECS container credentials protocols.
package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/vault"
)

func writeErrorMessage(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{"Message": msg}); err != nil {
		log.Println(err.Error())
	}
}

func withAuthorizationCheck(authToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authToken {
			writeErrorMessage(w, "invalid Authorization token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func writeCredsToResponse(creds aws.Credentials, w http.ResponseWriter) {
	err := json.NewEncoder(w).Encode(map[string]string{
		"AccessKeyId":     creds.AccessKeyID,
		"SecretAccessKey": creds.SecretAccessKey,
		"Token":           creds.SessionToken,
		"Expiration":      iso8601.Format(creds.Expires),
	})
	if err != nil {
		writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func generateRandomString() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// EcsServer serves credentials on localhost in the format of the ECS container credentials endpoint.
type EcsServer struct {
	listener          net.Listener
	authToken         string
	server            http.Server
	cache             sync.Map
	baseCredsProvider aws.CredentialsProvider
	config            *vault.ProfileConfig
}

// NewEcsServer listens on 127.0.0.1:port and returns a server for baseCredsProvider's credentials. An
// empty authToken gets a random one. Unless lazyLoadBaseCreds is set, the credentials are fetched
// straight away, so errors show up at startup.
func NewEcsServer(ctx context.Context, baseCredsProvider aws.CredentialsProvider, config *vault.ProfileConfig, authToken string, port int, lazyLoadBaseCreds bool) (*EcsServer, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	if authToken == "" {
		authToken = generateRandomString()
	}

	credsCache := aws.NewCredentialsCache(baseCredsProvider)
	if !lazyLoadBaseCreds {
		_, err := credsCache.Retrieve(ctx)
		if err != nil {
			return nil, fmt.Errorf("retrieving creds: %w", err)
		}
	}

	e := &EcsServer{
		listener:          listener,
		authToken:         authToken,
		baseCredsProvider: credsCache,
		config:            config,
	}

	router := http.NewServeMux()
	router.HandleFunc("/", e.DefaultRoute)
	router.HandleFunc("/role-arn/", e.AssumeRoleArnRoute)
	e.server.Handler = withLogging(withAuthorizationCheck(e.authToken, router.ServeHTTP))

	return e, nil
}

// BaseURL returns the URL the server listens on.
func (e *EcsServer) BaseURL() string {
	return fmt.Sprintf("http://%s", e.listener.Addr().String())
}

// AuthToken returns the token clients must send in the Authorization header.
func (e *EcsServer) AuthToken() string {
	return e.authToken
}

// Serve serves requests until the server is shut down.
func (e *EcsServer) Serve() error {
	return e.server.Serve(e.listener)
}

// DefaultRoute responds with the base profile's credentials.
func (e *EcsServer) DefaultRoute(w http.ResponseWriter, r *http.Request) {
	creds, err := e.baseCredsProvider.Retrieve(r.Context())
	if err != nil {
		writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeCredsToResponse(creds, w)
}

func (e *EcsServer) getRoleProvider(roleArn string) aws.CredentialsProvider {
	var roleProviderCache *aws.CredentialsCache

	v, ok := e.cache.Load(roleArn)
	if ok {
		roleProviderCache = v.(*aws.CredentialsCache)
	} else {
		cfg := vault.NewAwsConfigWithCredsProvider(e.baseCredsProvider, e.config.Region, e.config.STSRegionalEndpoints, e.config.EndpointURL)
		roleProvider := &vault.AssumeRoleProvider{
			StsClient: sts.NewFromConfig(cfg),
			RoleARN:   roleArn,
			Duration:  e.config.AssumeRoleDuration,
		}
		roleProviderCache = aws.NewCredentialsCache(roleProvider)
		e.cache.Store(roleArn, roleProviderCache)
	}
	return roleProviderCache
}

// AssumeRoleArnRoute responds with credentials for the role ARN in the request path.
func (e *EcsServer) AssumeRoleArnRoute(w http.ResponseWriter, r *http.Request) {
	roleArn := strings.TrimPrefix(r.URL.Path, "/role-arn/")
	roleProvider := e.getRoleProvider(roleArn)
	creds, err := roleProvider.Retrieve(r.Context())
	if err != nil {
		writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeCredsToResponse(creds, w)
}
