package logger

import (
	"log/slog"
	"os"
)

// Logger defines the interface for logging operations
type Logger interface {
	Log(level slog.Level, message string, fields ...any)
}

// CFLogger implements the Logger interface
type CFLogger struct {
	logger   *slog.Logger
	logLevel slog.Level
}

func NewCFLogger() *CFLogger {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(handler)

	return &CFLogger{
		logger:   logger,
		logLevel: slog.LevelInfo,
	}
}

func (l *CFLogger) Log(level slog.Level, message string, fields ...any) {
	if level >= l.logLevel {
		switch level {
		case slog.LevelDebug:
			l.logger.Debug(message, fields...)
		case slog.LevelInfo:
			l.logger.Info(message, fields...)
		case slog.LevelWarn:
			l.logger.Warn(message, fields...)
		case slog.LevelError:
			l.logger.Error(message, fields...)
		}
	}
}
