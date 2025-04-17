package watchdog

import (
	"context"
	"fmt"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/internal/logger"

	"github.com/coreos/go-systemd/v22/daemon"
)

const (
	defaultWatchdogInterval         = 120 * time.Second
	defaultNotificationsPerInterval = 8
)

type Watchdog struct {
	log                      logger.Logger
	watchdogInterval         time.Duration
	totalNotifications       int
	notificationsPerInterval int // Number of times to notify within each interval
}

// New creates a new Watchdog instance
func New(log logger.Logger) (*Watchdog, error) {
	interval, err := daemon.SdWatchdogEnabled(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get watchdog interval: %w", err)
	}

	if interval == 0 {
		interval = defaultWatchdogInterval
	}

	return &Watchdog{
		log:                      log.With("component", "watchdog"),
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
	w.log.Info("Starting watchdog",
		"interval", w.watchdogInterval.String(),
		"notifications_per_interval", w.notificationsPerInterval)

	// Calculate tick interval to achieve desired number of notifications per interval
	notificationInterval := w.watchdogInterval / time.Duration(w.notificationsPerInterval)
	ticker := time.NewTicker(notificationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.log.Info("Stopping watchdog", "total_notifications", w.totalNotifications)
			return nil
		case <-ticker.C:
			if err := w.notify(); err != nil {
				w.log.Error("Failed to notify watchdog", "error", err)
			}
		}
	}
}

// notify sends a keepalive signal to systemd
func (w *Watchdog) notify() error {
	if ok, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); !ok || err != nil {
		return fmt.Errorf("failed to notify systemd watchdog: %v", err)
	}
	w.totalNotifications++
	w.log.Debug("Watchdog notified", "total_notifications", w.totalNotifications)
	return nil
}
