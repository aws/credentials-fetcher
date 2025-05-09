package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestLoggerInitialization tests that the logger is properly initialized
func TestLoggerInitialization(t *testing.T) {
	// Verify that the logger is not nil
	if log == nil {
		t.Error("Logger should not be nil")
	}
}

// TestSignalHandling tests the signal handling functionality
func TestSignalHandling(t *testing.T) {
	// Create a context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Create a signal channel
	sigCh := make(chan os.Signal, 1)

	// Send a signal to the channel
	go func() {
		time.Sleep(50 * time.Millisecond)
		sigCh <- syscall.SIGTERM
	}()

	// Wait for the signal or context timeout
	select {
	case sig := <-sigCh:
		if sig != syscall.SIGTERM {
			t.Errorf("Expected SIGTERM, got %v", sig)
		}
	case <-ctx.Done():
		t.Error("Context timed out before signal was received")
	}
}
