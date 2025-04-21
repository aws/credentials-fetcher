package watchdog

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockLogger implements logger.Logger
type mockLogger struct {
	mock.Mock
}

func (m *mockLogger) Log(level slog.Level, message string, fields ...any) {
	args := []interface{}{level, message}
	args = append(args, fields...)
	m.Called(args...)
}

func TestNew(t *testing.T) {
	mockLog := &mockLogger{}
	watchdog, err := New(mockLog)

	assert.NoError(t, err)
	assert.NotNil(t, watchdog)
	assert.Equal(t, mockLog, watchdog.log)
}

func TestStart(t *testing.T) {
	mockLog := &mockLogger{}
	watchdog, _ := New(mockLog)

	// Set a short interval for testing
	watchdog.watchdogInterval = 100 * time.Millisecond
	watchdog.notificationsPerInterval = 1

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	mockLog.On("Log", slog.LevelInfo, "Starting watchdog", "interval", "100ms", "notifications_per_interval", 1).Once()
	mockLog.On("Log", slog.LevelError, "Failed to notify watchdog", "error", mock.MatchedBy(func(err error) bool {
		return err.Error() == "failed to notify systemd watchdog: <nil>"
	})).Times(2)
	mockLog.On("Log", slog.LevelInfo, "Stopping watchdog", "total_notifications", 0).Once()

	err := watchdog.Start(ctx)

	assert.NoError(t, err)
	mockLog.AssertExpectations(t)
}

func TestIsSystemdEnabled(t *testing.T) {
	// Since we can't easily mock the systemd functions, we just verify it returns false
	// when not running under systemd
	assert.False(t, IsSystemdEnabled())
}
