package logger

import (
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

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
	done    chan struct{}
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
	l := &logger{
		Logger:  slog.New(handler),
		logFile: logFile,
		done:    make(chan struct{}),
	}

	// Start periodic log rotation check
	if logFile != nil {
		go l.logRotationLoop()
	}

	return l
}

// setupLogFile creates the log directory and opens the log file
func setupLogFile() (*os.File, error) {
	// Create log directory with 0755 permissions
	// #nosec G301 - 0755 permissions required per spec for log directory accessibility
	if err := os.MkdirAll(constants.LogDirectory, 0755); err != nil {
		return nil, err
	}

	// Truncate log file if it exceeds max size (10 MB)
	truncateLogFileIfNeeded(constants.LogFilePath)

	// Open/create log file with append mode and 0644 permissions
	logFile, err := os.OpenFile(constants.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) // #nosec G302
	if err != nil {
		return nil, err
	}

	return logFile, nil
}

// maxLogFileSize is the maximum log file size before truncation (10 MB)
const maxLogFileSize = 10 * 1024 * 1024

// truncateLogFileIfNeeded truncates the log file if it exceeds maxLogFileSize.
// This matches the behavior of the C++ credentials-fetcher (v1.3.8).
func truncateLogFileIfNeeded(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return // file doesn't exist yet, nothing to truncate
	}
	if info.Size() > maxLogFileSize {
		_ = os.Truncate(path, 0)
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

// Close closes the log file if it's open
func (l *logger) Close() error {
	if l.done != nil {
		close(l.done)
	}
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// logRotationLoop periodically checks log file size and truncates if needed
func (l *logger) logRotationLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			truncateLogFileIfNeeded(constants.LogFilePath)
		case <-l.done:
			return
		}
	}
}
