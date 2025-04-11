package main

import (
	"context"

	"golang.a2z.com/CredentialsFetcherV2/internal"
)

// newHandler returns a lambda handler which is configured to call summer to perform the required calculation.
// Given how basic this service is there's no reason you couldn't refactor this function to be shared between this
// lambda and the subtract lambda but most services aren't going to be that simple.
// Instead, the purpose of "summer" is to show how one might wire handlers with clients (think AWS clients).
func newHandler(summer func(ctx context.Context, x, y float64) float64) func(ctx context.Context, req request) (*response, error) {
	return func(ctx context.Context, req request) (res *response, finalErr error) {
		mEntry, closeEntry := internal.NewMetrics(ctx)
		defer func() {
			closeEntry(finalErr == nil)
		}()
		logger := internal.NewLogger(ctx)

		// Store the logger & metrics entries on the context for use by wired-in functions like `summer`.
		ctx = internal.LoggerToCtx(ctx, logger)
		ctx = internal.MetricsToCtx(ctx, mEntry)

		logger.WithField("req", req).Info("handler invoked")
		defer func() {
			logger.WithField("res", res).WithError(finalErr).Info("handler returning")
		}()

		if err := req.validate(); err != nil {
			return &response{
				Error: &responseError{
					Code:    "InvalidRequest",
					Message: err.Error(),
				},
			}, nil
		}

		result := summer(ctx, req.X, req.Y)

		return &response{
			Result: result,
		}, nil
	}
}
