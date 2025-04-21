package logger

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockCFLogger struct {
	mock.Mock
}

func (m *MockCFLogger) Log(level slog.Level, message string, fields ...any) {
	args := []interface{}{level, message}
	args = append(args, fields...)
	m.Called(args...)
}

func TestNewCFLogger(t *testing.T) {
	logger := NewCFLogger()
	assert.NotNil(t, logger, "NewCFLogger() should not return nil")
}

func setupTestLogger() (*CFLogger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	return &CFLogger{
		logger:   logger,
		logLevel: slog.LevelDebug,
	}, buf
}

func TestLog(t *testing.T) {
	tests := []struct {
		name    string
		level   slog.Level
		message string
		fields  []any
	}{
		{
			name:    "Info level",
			level:   slog.LevelInfo,
			message: "info message",
		},
		{
			name:    "Debug level",
			level:   slog.LevelDebug,
			message: "debug message",
		},
		{
			name:    "Error with fields",
			level:   slog.LevelError,
			message: "error occurred",
			fields:  []any{"error", "test error", "code", 500},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, buf := setupTestLogger()

			logger.Log(tt.level, tt.message, tt.fields...)

			output := buf.String()
			assert.Contains(t, output, tt.level.String())
			assert.Contains(t, output, tt.message)

			// Check fields if present
			if len(tt.fields) > 0 {
				for i := 0; i < len(tt.fields); i += 2 {
					if i+1 < len(tt.fields) {
						key := tt.fields[i].(string)
						value := tt.fields[i+1]
						assert.Contains(t, output, key)
						assert.Contains(t, output, stringifyValue(value))
					}
				}
			}
		})
	}
}

// Helper function to convert values to string representation
func stringifyValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return fmt.Sprintf("%d", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}
