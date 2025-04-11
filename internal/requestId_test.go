package internal

import (
	"context"
	"testing"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/stretchr/testify/assert"
)

func Test_RequestId(t *testing.T) {
	tests := map[string]struct {
		Ctx               context.Context
		ExpectedRequestID string
	}{
		"test found": {
			Ctx: lambdacontext.NewContext(context.Background(), &lambdacontext.LambdaContext{
				AwsRequestID: "012345",
			}),
			ExpectedRequestID: "012345",
		},
		"test unknown": {
			Ctx:               context.Background(),
			ExpectedRequestID: "unknown",
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requestID := RequestId(test.Ctx)
			assert.Equal(t, test.ExpectedRequestID, requestID, "requestID does not match expected value")
		})
	}
}
