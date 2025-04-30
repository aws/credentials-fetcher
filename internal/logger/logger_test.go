package logger

import (
	"bytes"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testHandler struct {
	*slog.TextHandler
	buf *bytes.Buffer
}

// Reset the singleton instance for testing
func resetSingleton() {
	instance = nil
	once = sync.Once{}
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

func TestGetInstance(t *testing.T) {
	resetSingleton()
	logger := GetInstance()
	assert.NotNil(t, logger, "GetInstance() should not return nil")

	// Test that we get the same instance on subsequent calls
	logger2 := GetInstance()
	assert.Equal(t, logger, logger2, "GetInstance() should return the same instance")
}

func TestLogLevelFromEnvironment(t *testing.T) {
	// Save original environment and restore it after the test
	originalLogLevel := os.Getenv("LOG_LEVEL")
	defer os.Setenv("LOG_LEVEL", originalLogLevel)

	testCases := []struct {
		name          string
		envLevel      string
		expectedLevel string
		testMessage   string
	}{
		{
			name:          "Debug level",
			envLevel:      "debug",
			expectedLevel: "DEBUG",
			testMessage:   "debug test message",
		},
		{
			name:          "Info level",
			envLevel:      "info",
			expectedLevel: "INFO",
			testMessage:   "info test message",
		},
		{
			name:          "Warn level",
			envLevel:      "warn",
			expectedLevel: "WARN",
			testMessage:   "warn test message",
		},
		{
			name:          "Error level",
			envLevel:      "error",
			expectedLevel: "ERROR",
			testMessage:   "error test message",
		},
		{
			name:          "Invalid level defaults to Info",
			envLevel:      "invalid",
			expectedLevel: "INFO",
			testMessage:   "default test message",
		},
		{
			name:          "Empty level defaults to Info",
			envLevel:      "",
			expectedLevel: "INFO",
			testMessage:   "empty level test message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset singleton for each test case
			resetSingleton()

			// Set environment variable for this test case
			os.Setenv("LOG_LEVEL", tc.envLevel)

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Create logger and log a message
			log := GetInstance()

			// Log at all levels to test filtering
			log.Debug("debug " + tc.testMessage)
			log.Info("info " + tc.testMessage)
			log.Warn("warn " + tc.testMessage)
			log.Error("error " + tc.testMessage)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			_, err := buf.ReadFrom(r)
			require.NoError(t, err)
			output := buf.String()

			// Verify expected behavior based on log level
			switch tc.envLevel {
			case "debug":
				assert.Contains(t, output, "DEBUG", "Debug messages should be logged")
				assert.Contains(t, output, "INFO", "Info messages should be logged")
				assert.Contains(t, output, "WARN", "Warn messages should be logged")
				assert.Contains(t, output, "ERROR", "Error messages should be logged")
			case "info":
				assert.NotContains(t, output, "DEBUG", "Debug messages should not be logged")
				assert.Contains(t, output, "INFO", "Info messages should be logged")
				assert.Contains(t, output, "WARN", "Warn messages should be logged")
				assert.Contains(t, output, "ERROR", "Error messages should be logged")
			case "warn":
				assert.NotContains(t, output, "DEBUG", "Debug messages should not be logged")
				assert.NotContains(t, output, "INFO", "Info messages should not be logged")
				assert.Contains(t, output, "WARN", "Warn messages should be logged")
				assert.Contains(t, output, "ERROR", "Error messages should be logged")
			case "error":
				assert.NotContains(t, output, "DEBUG", "Debug messages should not be logged")
				assert.NotContains(t, output, "INFO", "Info messages should not be logged")
				assert.NotContains(t, output, "WARN", "Warn messages should not be logged")
				assert.Contains(t, output, "ERROR", "Error messages should be logged")
			default:
				// Default is INFO level
				assert.NotContains(t, output, "DEBUG", "Debug messages should not be logged")
				assert.Contains(t, output, "INFO", "Info messages should be logged")
				assert.Contains(t, output, "WARN", "Warn messages should be logged")
				assert.Contains(t, output, "ERROR", "Error messages should be logged")
			}
		})
	}
}
