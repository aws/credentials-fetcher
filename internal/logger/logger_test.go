package logger

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogger_New(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logger-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name        string
		config      Config
		expectError bool
	}{
		{
			name: "Valid production config",
			config: Config{
				LogLevel: "info",
				LogFile:  filepath.Join(tempDir, "test.log"),
			},
			expectError: false,
		},
		{
			name: "Valid development config",
			config: Config{
				LogLevel:    "debug",
				Development: true,
			},
			expectError: false,
		},
		{
			name: "Invalid log level",
			config: Config{
				LogLevel: "invalid",
			},
			expectError: true,
		},
		{
			name: "Empty log level",
			config: Config{
				LogLevel: "",
			},
			expectError: true,
		},
		{
			name: "Invalid log file path",
			config: Config{
				LogLevel: "info",
				LogFile:  "/nonexistent/dir/test.log",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := New(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, logger)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
			}
		})
	}
}

func TestLoggerMethods(t *testing.T) {
	core, recorded := observer.New(zapcore.DebugLevel)
	testLogger := &zapLogger{zap.New(core)}

	tests := []struct {
		method      string
		logFunc     func(string, ...interface{})
		expectedLvl zapcore.Level
	}{
		{"Debug", testLogger.Debug, zapcore.DebugLevel},
		{"Info", testLogger.Info, zapcore.InfoLevel},
		{"Warn", testLogger.Warn, zapcore.WarnLevel},
		{"Error", testLogger.Error, zapcore.ErrorLevel},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			tt.logFunc("test message", "key", "value")
			assert.Equal(t, 1, recorded.Len())
			entry := recorded.All()[0]
			assert.Equal(t, tt.expectedLvl, entry.Level)
			assert.Equal(t, "test message", entry.Message)
			assert.Equal(t, "value", entry.ContextMap()["key"])
			recorded.TakeAll()
		})
	}
}

func TestLoggerWith(t *testing.T) {
	core, recorded := observer.New(zapcore.DebugLevel)
	testLogger := &zapLogger{zap.New(core)}

	withLogger := testLogger.With("constant", "value")
	withLogger.Info("test message", "key", "value")

	assert.Equal(t, 1, recorded.Len())
	entry := recorded.All()[0]
	assert.Equal(t, zapcore.InfoLevel, entry.Level)
	assert.Equal(t, "test message", entry.Message)
	assert.Equal(t, "value", entry.ContextMap()["constant"])
	assert.Equal(t, "value", entry.ContextMap()["key"])
}

func TestInterfaceToFields(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected []zap.Field
	}{
		{
			name:     "Empty input",
			input:    []interface{}{},
			expected: []zap.Field{},
		},
		{
			name:     "Single pair",
			input:    []interface{}{"key", "value"},
			expected: []zap.Field{zap.Any("key", "value")},
		},
		{
			name:     "Multiple pairs",
			input:    []interface{}{"key1", "value1", "key2", 42},
			expected: []zap.Field{zap.Any("key1", "value1"), zap.Any("key2", 42)},
		},
		{
			name:     "Odd number of inputs",
			input:    []interface{}{"key1", "value1", "key2"},
			expected: []zap.Field{zap.Any("key1", "value1"), zap.Any("key2", "")},
		},
		{
			name:     "Non-string key",
			input:    []interface{}{42, "value"},
			expected: []zap.Field{zap.Any("42", "value")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := interfaceToFields(tt.input...)
			assert.Equal(t, len(tt.expected), len(result))
			for i, field := range result {
				assert.Equal(t, tt.expected[i].Key, field.Key)
				assert.Equal(t, tt.expected[i].String, field.String)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
	}{
		{
			name:        "Valid config",
			config:      Config{LogLevel: "info"},
			expectError: false,
		},
		{
			name:        "Empty log level",
			config:      Config{LogLevel: ""},
			expectError: true,
		},
		{
			name:        "Invalid log level",
			config:      Config{LogLevel: "invalid"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewNop(t *testing.T) {
	nopLogger := NewNop()
	assert.NotNil(t, nopLogger)

	// Ensure no panics occur when using NopLogger
	nopLogger.Debug("test")
	nopLogger.Info("test")
	nopLogger.Warn("test")
	nopLogger.Error("test")
	nopLogger.With("key", "value").Info("test")
	err := nopLogger.Sync()
	assert.NoError(t, err)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.Equal(t, "info", config.LogLevel)
	assert.False(t, config.Development)
	assert.Empty(t, config.LogFile)
}

func TestLogOutput(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logger-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "test.log")

	cfg := Config{
		LogLevel:    "debug",
		LogFile:     logFile,
		Development: false,
	}
	logger, err := New(cfg)
	require.NoError(t, err)

	logger.Debug("test debug message")
	logger.Info("test info message", "key", "value")
	logger.Error("test error message", "error", "some error")

	_ = logger.Sync()

	content, err := os.ReadFile(logFile)
	require.NoError(t, err)

	logContent := string(content)

	assert.Contains(t, logContent, "test debug message")
	assert.Contains(t, logContent, "test info message")
	assert.Contains(t, logContent, "test error message")

	assert.Contains(t, logContent, `"key":"value"`)
	assert.Contains(t, logContent, `"error":"some error"`)
}

func TestLoggerWithContext(t *testing.T) {
	core, recorded := observer.New(zapcore.DebugLevel)
	testLogger := &zapLogger{zap.New(core)}

	contextLogger := testLogger.With("context", "value")
	contextLogger.Info("test message", "key", "value")

	assert.Equal(t, 1, recorded.Len())
	entry := recorded.All()[0]
	assert.Equal(t, zapcore.InfoLevel, entry.Level)
	assert.Equal(t, "test message", entry.Message)
	assert.Equal(t, "value", entry.ContextMap()["context"])
	assert.Equal(t, "value", entry.ContextMap()["key"])
}

func TestLoggerEdgeCases(t *testing.T) {
	logger, err := New(Config{LogLevel: "info"})
	require.NoError(t, err)

	logger.Info("nil value", "key", nil)

	logger.Info("mixed types", "int", 42, "float", 3.14, "bool", true, "string", "value")

	logger.Info("")

	// No panic should occur in any of these cases
}

func TestNewWithInvalidConfig(t *testing.T) {
	_, err := New(Config{LogLevel: "invalid"})
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "invalid log level"))
}

func TestLoggerWithError(t *testing.T) {
	core, recorded := observer.New(zapcore.ErrorLevel)
	testLogger := &zapLogger{zap.New(core)}

	testErr := errors.New("test error")
	testLogger.Error("error occurred", "error", testErr)

	require.Equal(t, 1, recorded.Len())
	entry := recorded.All()[0]
	assert.Equal(t, zapcore.ErrorLevel, entry.Level)
	assert.Equal(t, "error occurred", entry.Message)

	errValue := entry.ContextMap()["error"]
	assert.Equal(t, testErr.Error(), errValue.(string))
}
