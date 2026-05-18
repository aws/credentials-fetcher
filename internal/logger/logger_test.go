package logger

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	defer func(key, value string) {
		err := os.Setenv(key, value)
		if err != nil {
			fmt.Printf("%s", err.Error())
		}
	}("LOG_LEVEL", originalLogLevel)

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
			err := os.Setenv("LOG_LEVEL", tc.envLevel)
			if err != nil {
				fmt.Printf("%s", err.Error())
				return
			}

			// Capture stdout
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			// Create logger and log a message
			log := GetInstance()

			// Log at all levels to test filtering
			log.Debug("debug " + tc.testMessage)
			log.Info("info " + tc.testMessage)
			log.Warn("warn " + tc.testMessage)
			log.Error("error " + tc.testMessage)

			// Restore stdout
			if err := w.Close(); err != nil {
				t.Fatalf("Failed to close writer: %v", err)
			}
			os.Stderr = oldStderr

			// Read captured output
			var buf bytes.Buffer
			_, err = buf.ReadFrom(r)
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

// TestDualOutputProperty tests that log messages appear in both stderr and file
func TestDualOutputProperty(t *testing.T) {
	tempDir := t.TempDir()
	testLogFile := filepath.Join(tempDir, "test.log")

	logFile, err := os.OpenFile(testLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer func() { _ = logFile.Close() }()

	// Capture stdout
	oldStderr := os.Stderr
	stdoutReader, stdoutWriter, _ := os.Pipe()
	os.Stderr = stdoutWriter

	// Create MultiWriter
	multiWriter := io.MultiWriter(stdoutWriter, logFile)
	handler := slog.NewTextHandler(multiWriter, &slog.HandlerOptions{Level: slog.LevelInfo})
	testLogger := &logger{Logger: slog.New(handler), logFile: logFile}

	testLogger.Info("test message", "key", "value")

	_ = stdoutWriter.Close()
	os.Stderr = oldStderr

	// Read stdout output
	var stdoutBuf bytes.Buffer
	_, err = stdoutBuf.ReadFrom(stdoutReader)
	require.NoError(t, err)
	stdoutOutput := stdoutBuf.String()

	// Read file output
	fileContent, err := os.ReadFile(testLogFile)
	require.NoError(t, err)
	fileOutput := string(fileContent)

	// Verify message appears in both outputs
	assert.Contains(t, stdoutOutput, "test message")
	assert.Contains(t, fileOutput, "test message")
}

// TestFilePermissions tests directory and file are created with correct permissions
func TestFilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	testLogDir := filepath.Join(tempDir, "logging")
	testLogFile := filepath.Join(testLogDir, "test.log")

	// Create directory and file
	err := os.MkdirAll(testLogDir, 0755)
	require.NoError(t, err)

	logFile, err := os.OpenFile(testLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer func() { _ = logFile.Close() }()

	// Verify directory permissions (0755)
	dirInfo, err := os.Stat(testLogDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), dirInfo.Mode().Perm())

	// Verify file permissions (0644)
	fileInfo, err := os.Stat(testLogFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), fileInfo.Mode().Perm())
}

// TestLoggerClose tests that the Close method properly closes the file handle
func TestLoggerClose(t *testing.T) {
	t.Run("Close with open file", func(t *testing.T) {
		tempDir := t.TempDir()
		testLogFile := filepath.Join(tempDir, "test.log")

		logFile, err := os.OpenFile(testLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)

		testLogger := &logger{
			Logger:  slog.New(slog.NewTextHandler(logFile, nil)),
			logFile: logFile,
		}

		err = testLogger.Close()
		assert.NoError(t, err)

		// Verify file is closed
		_, err = logFile.Write([]byte("test"))
		assert.Error(t, err)
	})

	t.Run("Close with nil file", func(t *testing.T) {
		testLogger := &logger{
			Logger:  slog.New(slog.NewTextHandler(os.Stdout, nil)),
			logFile: nil,
		}

		err := testLogger.Close()
		assert.NoError(t, err)
	})
}

// TestFileLoggingAppendMode tests that logs are appended to existing file
func TestFileLoggingAppendMode(t *testing.T) {
	tempDir := t.TempDir()
	testLogFile := filepath.Join(tempDir, "test.log")

	// Write initial content
	err := os.WriteFile(testLogFile, []byte("initial log\n"), 0644)
	require.NoError(t, err)

	// Open in append mode and write new content
	logFile, err := os.OpenFile(testLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)

	handler := slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo})
	testLogger := &logger{Logger: slog.New(handler), logFile: logFile}

	testLogger.Info("appended log")
	_ = logFile.Close()

	// Verify both entries exist
	content, err := os.ReadFile(testLogFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "initial log")
	assert.Contains(t, string(content), "appended log")
}

// TestTruncateLogFileIfNeeded tests log file truncation at max size
func TestTruncateLogFileIfNeeded(t *testing.T) {
	t.Run("File under max size is not truncated", func(t *testing.T) {
		tempDir := t.TempDir()
		testLogFile := filepath.Join(tempDir, "test.log")

		// Write 1 MB of data
		data := make([]byte, 1*1024*1024)
		err := os.WriteFile(testLogFile, data, 0644)
		require.NoError(t, err)

		truncateLogFileIfNeeded(testLogFile)

		info, err := os.Stat(testLogFile)
		require.NoError(t, err)
		assert.Equal(t, int64(1*1024*1024), info.Size(), "File should not be truncated")
	})

	t.Run("File over max size is truncated", func(t *testing.T) {
		tempDir := t.TempDir()
		testLogFile := filepath.Join(tempDir, "test.log")

		// Write 11 MB of data (over 10 MB limit)
		data := make([]byte, 11*1024*1024)
		err := os.WriteFile(testLogFile, data, 0644)
		require.NoError(t, err)

		truncateLogFileIfNeeded(testLogFile)

		info, err := os.Stat(testLogFile)
		require.NoError(t, err)
		assert.Equal(t, int64(0), info.Size(), "File should be truncated to 0")
	})

	t.Run("Exactly at max size is not truncated", func(t *testing.T) {
		tempDir := t.TempDir()
		testLogFile := filepath.Join(tempDir, "test.log")

		// Write exactly 10 MB
		data := make([]byte, maxLogFileSize)
		err := os.WriteFile(testLogFile, data, 0644)
		require.NoError(t, err)

		truncateLogFileIfNeeded(testLogFile)

		info, err := os.Stat(testLogFile)
		require.NoError(t, err)
		assert.Equal(t, int64(maxLogFileSize), info.Size(), "File at exact limit should not be truncated")
	})

	t.Run("Non-existent file does not error", func(t *testing.T) {
		// Should not panic or error
		truncateLogFileIfNeeded("/tmp/nonexistent-log-file-xyz.log")
	})
}
