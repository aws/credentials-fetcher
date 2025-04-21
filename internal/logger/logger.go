package logger

import (
	"log/slog"
	"os"
)

// Logger is a simple interface for logging operations
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// logger implements the Logger interface
type logger struct {
	*slog.Logger
}

// New creates a new logger instance
func New() Logger {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	return &logger{
		Logger: slog.New(handler),
	}
}

func (l *logger) Debug(msg string, args ...any) {
	l.Logger.Debug(msg, args...)
}

func (l *logger) Info(msg string, args ...any) {
	l.Logger.Info(msg, args...)
}

func (l *logger) Warn(msg string, args ...any) {
	l.Logger.Warn(msg, args...)
}

func (l *logger) Error(msg string, args ...any) {
	l.Logger.Error(msg, args...)
}
