package internal

import (
	"context"

	"github.com/aws/aws-lambda-go/lambdacontext"
)

// RequestId returns the request for the given context.
// If run in a lambda function it'll be the AwsRequestId associated with the request.
// Otherwise it'll be "unknown".
func RequestId(ctx context.Context) string {
	lCtx, ok := lambdacontext.FromContext(ctx)
	if ok {
		return lCtx.AwsRequestID
	}
	return "unknown"
}
