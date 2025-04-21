package watchdog

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	watchdog, err := New()

	assert.NoError(t, err)
	assert.NotNil(t, watchdog)
	assert.Equal(t, defaultWatchdogInterval, watchdog.watchdogInterval)
	assert.Equal(t, defaultNotificationsPerInterval, watchdog.notificationsPerInterval)
}

func TestStart(t *testing.T) {
	watchdog, _ := New()

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
