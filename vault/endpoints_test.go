package vault

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var errCaptured = errors.New("request captured")

// captureClient records the last request instead of sending it.
type captureClient struct{ req *http.Request }

func (c *captureClient) Do(r *http.Request) (*http.Response, error) {
	c.req = r
	return nil, errCaptured
}

var credentialScope = regexp.MustCompile(`Credential=[^/]+/[^/]+/([^/]+)/([^/]+)/`)

// sentTo returns the URL a client call was sent to, and the region and
// service it was signed for, if any.
func sentTo(t *testing.T, c *captureClient) string {
	t.Helper()
	if c.req == nil {
		t.Fatal("no request was sent")
	}
	out := c.req.URL.Scheme + "://" + c.req.URL.Host + c.req.URL.Path
	if m := credentialScope.FindStringSubmatch(c.req.Header.Get("Authorization")); m != nil {
		out += " signed " + m[1] + "/" + m[2]
	}
	return out
}

// TestEndpointResolution records where each client sends requests, and the
// region they're signed for, for the endpoint settings aws-vault supports.
func TestEndpointResolution(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		region, stsRegional, endpoint string
		want                          [4]string // sts, iam, sso, ssooidc
	}{
		{
			name: "defaults", region: "eu-west-1", stsRegional: "", endpoint: "",
			want: [4]string{
				"https://sts.eu-west-1.amazonaws.com/ signed eu-west-1/sts",
				"https://iam.amazonaws.com/ signed us-east-1/iam",
				"https://portal.sso.eu-west-1.amazonaws.com/federation/credentials",
				"https://oidc.eu-west-1.amazonaws.com/client/register",
			},
		},
		{
			name: "regional", region: "eu-west-1", stsRegional: "regional", endpoint: "",
			want: [4]string{
				"https://sts.eu-west-1.amazonaws.com/ signed eu-west-1/sts",
				"https://iam.amazonaws.com/ signed us-east-1/iam",
				"https://portal.sso.eu-west-1.amazonaws.com/federation/credentials",
				"https://oidc.eu-west-1.amazonaws.com/client/register",
			},
		},
		{
			name: "legacy", region: "eu-west-1", stsRegional: "legacy", endpoint: "",
			want: [4]string{
				"https://sts.amazonaws.com/ signed eu-west-1/sts",
				"https://iam.amazonaws.com/ signed us-east-1/iam",
				"https://portal.sso.eu-west-1.amazonaws.com/federation/credentials",
				"https://oidc.eu-west-1.amazonaws.com/client/register",
			},
		},
		{
			name: "legacy us-east-1", region: "us-east-1", stsRegional: "legacy", endpoint: "",
			want: [4]string{
				"https://sts.amazonaws.com/ signed us-east-1/sts",
				"https://iam.amazonaws.com/ signed us-east-1/iam",
				"https://portal.sso.us-east-1.amazonaws.com/federation/credentials",
				"https://oidc.us-east-1.amazonaws.com/client/register",
			},
		},
		{
			name: "legacy, region not global", region: "af-south-1", stsRegional: "legacy", endpoint: "",
			want: [4]string{
				"https://sts.af-south-1.amazonaws.com/ signed af-south-1/sts",
				"https://iam.amazonaws.com/ signed us-east-1/iam",
				"https://portal.sso.af-south-1.amazonaws.com/federation/credentials",
				"https://oidc.af-south-1.amazonaws.com/client/register",
			},
		},
		{
			name: "legacy, china", region: "cn-north-1", stsRegional: "legacy", endpoint: "",
			want: [4]string{
				"https://sts.cn-north-1.amazonaws.com.cn/ signed cn-north-1/sts",
				"https://iam.cn-north-1.amazonaws.com.cn/ signed cn-north-1/iam",
				"https://portal.sso.cn-north-1.amazonaws.com.cn/federation/credentials",
				"https://oidc.cn-north-1.amazonaws.com.cn/client/register",
			},
		},
		{
			name: "govcloud", region: "us-gov-west-1", stsRegional: "", endpoint: "",
			want: [4]string{
				"https://sts.us-gov-west-1.amazonaws.com/ signed us-gov-west-1/sts",
				"https://iam.us-gov.amazonaws.com/ signed us-gov-west-1/iam",
				"https://portal.sso.us-gov-west-1.amazonaws.com/federation/credentials",
				"https://oidc.us-gov-west-1.amazonaws.com/client/register",
			},
		},
		{
			name: "endpoint_url", region: "eu-west-1", stsRegional: "", endpoint: "http://localhost:4566",
			want: [4]string{
				"http://localhost:4566/ signed eu-west-1/sts",
				"http://localhost:4566/ signed eu-west-1/iam",
				"http://localhost:4566/federation/credentials",
				"http://localhost:4566/client/register",
			},
		},
		{
			name: "endpoint_url with path", region: "eu-west-1", stsRegional: "", endpoint: "https://proxy.example.com/aws",
			want: [4]string{
				"https://proxy.example.com/aws/ signed eu-west-1/sts",
				"https://proxy.example.com/aws/ signed eu-west-1/iam",
				"https://proxy.example.com/aws/federation/credentials",
				"https://proxy.example.com/aws/client/register",
			},
		},
		{
			name: "endpoint_url and legacy", region: "eu-west-1", stsRegional: "legacy", endpoint: "http://localhost:4566",
			want: [4]string{
				"http://localhost:4566/ signed eu-west-1/sts",
				"http://localhost:4566/ signed eu-west-1/iam",
				"http://localhost:4566/federation/credentials",
				"http://localhost:4566/client/register",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := &captureClient{}
			cfg := NewAwsConfigWithCredsProvider(credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""), tc.region, tc.stsRegional, tc.endpoint)
			cfg.HTTPClient = c
			cfg.RetryMaxAttempts = 1

			var got [4]string
			_, _ = sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			got[0] = sentTo(t, c)
			_, _ = iam.NewFromConfig(cfg).GetUser(ctx, &iam.GetUserInput{})
			got[1] = sentTo(t, c)
			_, _ = sso.NewFromConfig(cfg).GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{AccessToken: aws.String("t"), AccountId: aws.String("111111111111"), RoleName: aws.String("r")})
			got[2] = sentTo(t, c)
			_, _ = ssooidc.NewFromConfig(cfg).RegisterClient(ctx, &ssooidc.RegisterClientInput{ClientName: aws.String("n"), ClientType: aws.String("public")})
			got[3] = sentTo(t, c)

			for i, service := range []string{"sts", "iam", "sso", "ssooidc"} {
				if got[i] != tc.want[i] {
					t.Errorf("%s: sent to %s, want %s", service, got[i], tc.want[i])
				}
			}
		})
	}
}
