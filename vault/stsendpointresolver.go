package vault

import (
	"context"
	"log"
	"slices"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// legacySTSRegions use the global STS endpoint when sts_regional_endpoints is "legacy", see
// https://docs.aws.amazon.com/credref/latest/refdocs/setting-global-sts_regional_endpoints.html
var legacySTSRegions = []string{
	"ap-northeast-1", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "aws-global",
	"ca-central-1", "eu-central-1", "eu-north-1", "eu-west-1", "eu-west-2", "eu-west-3",
	"sa-east-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2",
}

// addLegacySTSEndpoint sends STS requests in legacySTSRegions to the global endpoint.
// It runs after endpoint resolution and before signing, so requests are still
// signed for their region.
func addLegacySTSEndpoint(stack *middleware.Stack) error {
	return stack.Finalize.Insert(middleware.FinalizeMiddlewareFunc("LegacySTSEndpoint",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
			req, ok := in.Request.(*smithyhttp.Request)
			if ok && awsmiddleware.GetServiceID(ctx) == sts.ServiceID && slices.Contains(legacySTSRegions, awsmiddleware.GetRegion(ctx)) {
				log.Println("Using legacy STS endpoint sts.amazonaws.com")
				req.URL.Scheme = "https"
				req.URL.Host = "sts.amazonaws.com"
			}
			return next.HandleFinalize(ctx, in)
		}), "ResolveEndpointV2", middleware.After)
}
