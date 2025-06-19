package watchdog

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/internal/logger"

	"github.com/coreos/go-systemd/v22/daemon"
)

const (
	defaultWatchdogInterval         = 120 * time.Second
	defaultNotificationsPerInterval = 8
)

var (
	log = logger.GetInstance()

	// Singleton instance
	instance     *Watchdog
	instanceErr  error
	instanceOnce sync.Once
)

type Watchdog struct {
	watchdogInterval         time.Duration
	notificationsPerInterval int // Number of times to notify within each interval
}

// GetInstance returns the singleton Watchdog instance
func GetInstance() (*Watchdog, error) {
	instanceOnce.Do(func() {
		instance, instanceErr = newWatchdog()
	})
	return instance, instanceErr
}

// newWatchdog creates a new Watchdog instance (internal use)
func newWatchdog() (*Watchdog, error) {
	interval, err := daemon.SdWatchdogEnabled(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get watchdog interval: %w", err)
	}

	if interval == 0 {
		interval = defaultWatchdogInterval
	}

	return &Watchdog{
		watchdogInterval:         interval,
		notificationsPerInterval: defaultNotificationsPerInterval,
	}, nil
}

// IsSystemdEnabled checks if the daemon is running under systemd
func IsSystemdEnabled() bool {
	ok, err := daemon.SdNotify(false, daemon.SdNotifyReady)
	if err != nil {
		return false
	}
	return ok
}

// Start begins the watchdog process
func (w *Watchdog) Start(ctx context.Context) error {
	log.Info("Starting watchdog",
		"interval", w.watchdogInterval.String(),
		"notifications_per_interval", w.notificationsPerInterval)

	// Calculate tick interval to achieve desired number of notifications per interval
	notificationInterval := w.watchdogInterval / time.Duration(w.notificationsPerInterval)
	ticker := time.NewTicker(notificationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping watchdog...")
			return nil
		case <-ticker.C:
			if err := w.notify(); err != nil {
				log.Error("Failed to notify watchdog", "error", err)
			}
		}
	}
}

// notify sends a keepalive signal to systemd
func (w *Watchdog) notify() error {
	if ok, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); !ok || err != nil {
		return fmt.Errorf("failed to notify systemd watchdog: %v", err)
	}
	log.Debug("Watchdog notified. Interval: ", w.watchdogInterval.String())
	return nil
}
