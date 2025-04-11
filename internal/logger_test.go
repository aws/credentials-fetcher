package internal

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewLogger(t *testing.T) {
	t.Run("NoOptions", func(t *testing.T) {
		ctx := context.Background()
		logger := NewLogger(ctx)
		assert.Equal(t, &logrus.JSONFormatter{}, logger.Logger.Formatter)
		assert.Equal(t, true, logger.Logger.ReportCaller)
		assert.Equal(t, logrus.InfoLevel, logger.Logger.Level)
		assert.Equal(t, logrus.Fields{"requestId": RequestId(ctx)}, logger.Data)
	})

	t.Run("WithOptions", func(t *testing.T) {
		ctx := context.Background()
		logger := NewLogger(ctx, func(logger *logrus.Logger) {
			logger.SetFormatter(&logrus.TextFormatter{})
		}, func(logger *logrus.Logger) {
			logger.SetReportCaller(false)
		}, func(logger *logrus.Logger) {
			logger.SetLevel(logrus.DebugLevel)
		})

		assert.Equal(t, &logrus.TextFormatter{}, logger.Logger.Formatter)
		assert.Equal(t, false, logger.Logger.ReportCaller)
		assert.Equal(t, logrus.DebugLevel, logger.Logger.Level)
		assert.Equal(t, logrus.Fields{"requestId": RequestId(ctx)}, logger.Data)
	})
}

func TestLoggerFromCtxAndLoggerToCtx(t *testing.T) {
	t.Run("NoOptions", func(t *testing.T) {
		ctx := context.Background()
		logger := LoggerFromCtx(ctx)
		assert.Equal(t, &logrus.JSONFormatter{}, logger.Logger.Formatter)
		assert.Equal(t, true, logger.Logger.ReportCaller)
		assert.Equal(t, logrus.InfoLevel, logger.Logger.Level)
		assert.Equal(t, logrus.Fields{"requestId": RequestId(ctx)}, logger.Data)
	})

	t.Run("WithOptions", func(t *testing.T) {
		ctx := context.Background()
		logger := NewLogger(ctx, func(logger *logrus.Logger) {
			logger.SetFormatter(&logrus.TextFormatter{})
		}, func(logger *logrus.Logger) {
			logger.SetReportCaller(false)
		}, func(logger *logrus.Logger) {
			logger.SetLevel(logrus.DebugLevel)
		})
		logger = LoggerFromCtx(LoggerToCtx(ctx, logger))
		assert.Equal(t, &logrus.TextFormatter{}, logger.Logger.Formatter)
		assert.Equal(t, false, logger.Logger.ReportCaller)
		assert.Equal(t, logrus.DebugLevel, logger.Logger.Level)
		assert.Equal(t, logrus.Fields{"requestId": RequestId(ctx)}, logger.Data)
	})
}
