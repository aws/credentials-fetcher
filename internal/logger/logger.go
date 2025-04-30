package logger

import (
	"log/slog"
	"os"
	"sync"
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

var (
	instance Logger
	once     sync.Once
)

// GetInstance returns the singleton logger instance
func GetInstance() Logger {
	once.Do(func() {
		instance = newLogger()
	})
	return instance
}

// newLogger creates a new logger instance (internal use)
func newLogger() Logger {
	// Determine log level from environment variable
	logLevel := slog.LevelInfo

	// Check for LOG_LEVEL environment variable
	if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
		switch envLevel {
		case "debug":
			logLevel = slog.LevelDebug
		case "info":
			logLevel = slog.LevelInfo
		case "warn":
			logLevel = slog.LevelWarn
		case "error":
			logLevel = slog.LevelError
		}
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
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
