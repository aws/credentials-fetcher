package logger

import (
	"io"
	"log/slog"
	"os"
	"sync"

	"golang.a2z.com/CredentialsFetcherV2/constants"
)

// Logger is a simple interface for logging operations
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Close() error
}

// logger implements the Logger interface
type logger struct {
	*slog.Logger
	logFile *os.File
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

	// Setup log file
	logFile, err := setupLogFile()
	var writer io.Writer = os.Stdout

	if err != nil {
		// Log error to stdout and continue with stdout-only logging
		slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})).
			Error("Failed to setup log file, continuing with stdout-only logging", "error", err)
	} else if logFile != nil {
		// Create MultiWriter for dual output
		writer = io.MultiWriter(os.Stdout, logFile)
	}

	handler := slog.NewTextHandler(writer, &slog.HandlerOptions{
		Level: logLevel,
	})
	return &logger{
		Logger:  slog.New(handler),
		logFile: logFile,
	}
}

// setupLogFile creates the log directory and opens the log file
func setupLogFile() (*os.File, error) {
	// Create log directory with 0755 permissions
	// #nosec G301 - 0755 permissions required per spec for log directory accessibility
	if err := os.MkdirAll(constants.LogDirectory, 0755); err != nil {
		return nil, err
	}

	// Open/create log file with append mode and 0644 permissions
	logFile, err := os.OpenFile(constants.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) // #nosec G302
	if err != nil {
		return nil, err
	}

	return logFile, nil
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

// Close closes the log file if it's open
func (l *logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}
