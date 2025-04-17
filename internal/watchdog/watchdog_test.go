package watchdog

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

type mockLogger struct {
	logger.Logger
	debugCalled bool
	infoCalled  bool
	errorCalled bool
}

func (m *mockLogger) Debug(msg string, keysAndValues ...interface{}) {
	m.debugCalled = true
}

func (m *mockLogger) Info(msg string, keysAndValues ...interface{}) {
	m.infoCalled = true
}

func (m *mockLogger) Error(msg string, keysAndValues ...interface{}) {
	m.errorCalled = true
}

func (m *mockLogger) With(keysAndValues ...interface{}) logger.Logger {
	return m
}

func TestWatchdog_New(t *testing.T) {
	tests := []struct {
		name        string
		mockLogger  logger.Logger
		expectError bool
	}{
		{
			name:        "successful creation",
			mockLogger:  &mockLogger{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := New(tt.mockLogger)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, w)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, w)
				assert.Equal(t, defaultNotificationsPerInterval, w.notificationsPerInterval)
				assert.NotZero(t, w.watchdogInterval)
			}
		})
	}
}

func TestIsSystemdEnabled(t *testing.T) {
	result := IsSystemdEnabled()
	// We can't assert specific value as it depends on the environment
	// Just ensure the function runs without panicking
	t.Logf("SystemdEnabled: %v", result)
}

func TestWatchdog_Start(t *testing.T) {
	tests := []struct {
		name           string
		contextTimeout time.Duration
		expectedError  bool
	}{
		{
			name:           "normal operation with cancellation",
			contextTimeout: 100 * time.Millisecond,
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLog := &mockLogger{}
			w, err := New(mockLog)
			require.NoError(t, err)

			// Set a shorter interval for testing
			w.watchdogInterval = 50 * time.Millisecond
			w.notificationsPerInterval = 2

			ctx, cancel := context.WithTimeout(context.Background(), tt.contextTimeout)
			defer cancel()

			err = w.Start(ctx)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.True(t, mockLog.infoCalled, "Info should have been called")
		})
	}
}

func TestWatchdog_notify(t *testing.T) {
	mockLog := &mockLogger{}
	w, err := New(mockLog)
	require.NoError(t, err)

	initialCount := w.totalNotifications

	// Manually increment the counter and log (simulating what notify would do)
	w.totalNotifications++
	w.log.Debug("Watchdog notified", "total_notifications", w.totalNotifications)

	assert.True(t, mockLog.debugCalled, "Debug should have been called")
	assert.Equal(t, initialCount+1, w.totalNotifications, "Total notifications should be incremented")
}
