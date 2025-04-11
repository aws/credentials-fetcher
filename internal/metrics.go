package internal

import (
	"context"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"golang.a2z.com/GoAmzn-Metrics/metrics"
)

const serviceName = "CredentialsFetcherV2"

// InitMetrics initializes the metrics generator and configures it for EMF.
// InitMetrics MUST be called in the `init` method of a lambda to ensure metrics are emitted.
// To customize the metrics generator call `metrics.SetGenerator` instead of `InitMetrics`.
func InitMetrics() {
	metrics.SetGenerator(&metrics.BasicGenerator{WriterFunc: metrics.EMFQueryLogWriterFunc})
}

// NewMetrics returns a new metrics entry along with a function to use to close the entry as successful or not.
// The requestId and service name are set as properties.
func NewMetrics(ctx context.Context) (metrics.Entry, func(bool)) {
	entry := metrics.Start(lambdacontext.FunctionName) // If not run in a Lambda this'll be blank.
	entry.SetProperty("requestId", RequestId(ctx))
	entry.SetProperty(metrics.KeyProgram, serviceName)
	return entry, func(success bool) {
		// Common metrics ref: https://w.amazon.com/bin/view/Coral/Metrics/Common
		fatalCount := 0
		if !success {
			fatalCount++
		}
		entry.AddCount("Fatal", float64(fatalCount), metrics.CTCount)
		metrics.End(entry)
	}
}

// ctxKeyMetricsEntry is used to store a metrics entry on the context.
type ctxKeyMetricsEntry struct{}

// MetricsFromCtx returns the metrics.Entry on the context.
// If not present on the context MetricsFromCtx will panic.
func MetricsFromCtx(ctx context.Context) metrics.Entry {
	v, ok := ctx.Value(ctxKeyMetricsEntry{}).(metrics.Entry)
	if !ok {
		panic("no metrics entry found on the context")
	}
	return v
}

// MetricsToCtx stores the metrics.Entry on the context and returns it.
func MetricsToCtx(ctx context.Context, entry metrics.Entry) context.Context {
	return context.WithValue(ctx, ctxKeyMetricsEntry{}, entry)
}
