package internal

import (
	"context"

	"github.com/sirupsen/logrus"
)

// NewLogger returns a new structured logger entry.
func NewLogger(ctx context.Context, opts ...LoggerOpt) *logrus.Entry {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetReportCaller(true)
	logger.SetLevel(logrus.InfoLevel)

	for _, opt := range opts {
		opt(logger)
	}

	return logger.WithField("requestId", RequestId(ctx))
}

// LoggerOpt allows you to customize the logger returned by NewLogger.
type LoggerOpt func(logger *logrus.Logger)

// ctxKeyLogger is used to store a logger on the context.
type ctxKeyLogger struct{}

// LoggerFromCtx returns the logrus.Entry on the context.
// If not present on the context a new one will be returned.
// The new logger will be the result of calling NewLogger with the provided context and no options.
func LoggerFromCtx(ctx context.Context) *logrus.Entry {
	v, ok := ctx.Value(ctxKeyLogger{}).(*logrus.Entry)
	if !ok {
		return NewLogger(ctx)
	}
	return v
}

// LoggerToCtx stores the logrus.Entry on the context and returns it.
func LoggerToCtx(ctx context.Context, entry *logrus.Entry) context.Context {
	return context.WithValue(ctx, ctxKeyLogger{}, entry)
}
