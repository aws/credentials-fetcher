package logger

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testHandler struct {
	*slog.TextHandler
	buf *bytes.Buffer
}

func newTestLogger() (Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	return &logger{Logger: slog.New(handler)}, buf
}

func TestLogger(t *testing.T) {
	tests := []struct {
		name    string
		logFn   func(Logger, string, ...any)
		level   string
		message string
		args    []any
	}{
		{
			name:    "Debug level",
			logFn:   Logger.Debug,
			level:   "DEBUG",
			message: "debug message",
			args:    []any{"key", "value"},
		},
		{
			name:    "Info level",
			logFn:   Logger.Info,
			level:   "INFO",
			message: "info message",
			args:    []any{"key", "value"},
		},
		{
			name:    "Warn level",
			logFn:   Logger.Warn,
			level:   "WARN",
			message: "warn message",
			args:    []any{"key", "value"},
		},
		{
			name:    "Error level",
			logFn:   Logger.Error,
			level:   "ERROR",
			message: "error message",
			args:    []any{"key", "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, buf := newTestLogger()
			tt.logFn(logger, tt.message, tt.args...)

			output := buf.String()
			assert.Contains(t, output, tt.level, "output should contain correct level")
			assert.Contains(t, output, tt.message, "output should contain message")
			assert.Contains(t, output, tt.args[0].(string), "output should contain first arg")
			assert.Contains(t, output, tt.args[1].(string), "output should contain second arg")
		})
	}
}

func TestNew(t *testing.T) {
	logger := New()
	assert.NotNil(t, logger, "New() should not return nil")
}
