package watchdog

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Reset the singleton instance for testing
func resetSingleton() {
	instance = nil
	instanceErr = nil
	instanceOnce = sync.Once{}
}

func TestGetInstance(t *testing.T) {
	resetSingleton()

	watchdog, err := GetInstance()

	assert.NoError(t, err)
	assert.NotNil(t, watchdog)
	assert.Equal(t, defaultWatchdogInterval, watchdog.watchdogInterval)
	assert.Equal(t, defaultNotificationsPerInterval, watchdog.notificationsPerInterval)

	// Test that we get the same instance on subsequent calls
	watchdog2, err2 := GetInstance()
	assert.NoError(t, err2)
	assert.Equal(t, watchdog, watchdog2, "GetInstance() should return the same instance")
}

func TestStart(t *testing.T) {
	resetSingleton()

	watchdog, _ := GetInstance()

	// Set a short interval for testing
	watchdog.watchdogInterval = 100 * time.Millisecond
	watchdog.notificationsPerInterval = 1

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	err := watchdog.Start(ctx)

	assert.NoError(t, err)
}

func TestIsSystemdEnabled(t *testing.T) {
	// Since we can't easily mock the systemd functions, we just verify it returns false
	// when not running under systemd
	assert.False(t, IsSystemdEnabled())
}
