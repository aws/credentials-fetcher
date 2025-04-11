package main

import (
	"context"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"golang.a2z.com/CredentialsFetcherV2/internal"
)

func init() {
	internal.InitMetrics()
}

func main() {
	lambda.Start(newHandler(func(ctx context.Context, x, y float64) float64 {
		logger := internal.LoggerFromCtx(ctx)
		mEntry := internal.MetricsFromCtx(ctx)

		start := time.Now()
		defer func() {
			mEntry.AddTime("CalculationTime", time.Since(start))
		}()

		logger.WithField("x", x).WithField("y", y).Info("performing summer function")

		return x + y
	}))
}
