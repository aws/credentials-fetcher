package internal

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.a2z.com/GoAmzn-Metrics/metrics"
)

func TestNewMetrics(t *testing.T) {
	// Also tests MetricsFromCtx & MetricsToCtx
	t.Run("Success", func(t *testing.T) {
		gen := metrics.FakeGenerator{}
		metrics.SetGenerator(&gen)
		mEntry, end := NewMetrics(context.Background())
		mEntry.SetProperty("PropertyName", "PropertyValue")
		mEntry.AddCount("CountName", 1, metrics.CTCount)
		mEntry.AddTime("TimeName", time.Minute)

		// Illustrate that the metrics entry put on and taken off the context is the same metrics entry.
		ctxMetricsEntry := MetricsFromCtx(MetricsToCtx(context.Background(), mEntry))
		ctxMetricsEntry.SetProperty("ContextPropertyName", "ContextPropertyValue")
		ctxMetricsEntry.AddCount("ContextCountName", 2, metrics.CTNone)
		ctxMetricsEntry.AddTime("ContextTimeName", time.Hour)

		end(true) // true = success

		gen.Entries()
		assert.Equal(t, 1, len(gen.Entries()))

		entry := gen.Entries()[0]
		assert.Equal(t, map[string]string{
			"requestId":           "unknown",
			"Program":             "CredentialsFetcherV2",
			"PropertyName":        "PropertyValue",
			"ContextPropertyName": "ContextPropertyValue",
		}, entry.Properties())
		assert.Equal(t, 3, len(entry.Counts()))

		cntr1 := entry.Counts()[0]
		assert.Equal(t, "ContextCountName", cntr1.Name)
		assert.Equal(t, float64(2), cntr1.Count)
		assert.Equal(t, metrics.CTNone, cntr1.Ct)

		cntr2 := entry.Counts()[1]
		assert.Equal(t, "CountName", cntr2.Name)
		assert.Equal(t, float64(1), cntr2.Count)
		assert.Equal(t, metrics.CTCount, cntr2.Ct)

		cntr3 := entry.Counts()[2]
		assert.Equal(t, "Fatal", cntr3.Name)
		assert.Equal(t, float64(0), cntr3.Count)
		assert.Equal(t, metrics.CTCount, cntr3.Ct)

		assert.Equal(t, 2, len(entry.Times()))

		timr1 := entry.Times()[0]
		assert.Equal(t, "ContextTimeName", timr1.Name)
		assert.Equal(t, time.Hour, timr1.Duration)

		timr2 := entry.Times()[1]
		assert.Equal(t, "TimeName", timr2.Name)
		assert.Equal(t, time.Minute, timr2.Duration)
	})

	t.Run("Fail", func(t *testing.T) {
		gen := metrics.FakeGenerator{}
		metrics.SetGenerator(&gen)
		_, end := NewMetrics(context.Background())
		end(false) // false = not successful

		gen.Entries()
		assert.Equal(t, 1, len(gen.Entries()))

		entry := gen.Entries()[0]
		assert.Equal(t, map[string]string{
			"requestId": "unknown",
			"Program":   "CredentialsFetcherV2",
		}, entry.Properties())
		assert.Equal(t, 1, len(entry.Counts()))

		cntr2 := entry.Counts()[0]
		assert.Equal(t, "Fatal", cntr2.Name)
		assert.Equal(t, float64(1), cntr2.Count)
		assert.Equal(t, metrics.CTCount, cntr2.Ct)
	})
}

func TestMetricsFromCtxPanic(t *testing.T) {
	assert.Panics(t, func() {
		MetricsFromCtx(context.Background())
	})
}
