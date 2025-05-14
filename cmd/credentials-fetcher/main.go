package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/grpc"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/watchdog"
)

var log = logger.GetInstance()

func main() {
	log.Info("Starting Credentials Fetcher Daemon")

	// Create a context that will be canceled on termination signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Info("Received termination signal", "signal", sig.String())
		cancel()
	}()

	// Check if running under systemd
	isSystemd := watchdog.IsSystemdEnabled()
	if isSystemd {
		log.Info("Running under systemd")
	} else {
		log.Info("Not running under systemd, watchdog notifications will be simulated")
	}

	// Create the watchdog
	wd, err := watchdog.GetInstance()
	if err != nil {
		log.Error("Failed to create watchdog", "error", err)
		os.Exit(1)
	}

	log.Info("Watchdog created successfully")

	// Create the gRPC server
	server := grpc.NewCredentialsFetcherServer(constants.DefaultKrbFilesDir, constants.DefaultAWSSecretName)

	var wg sync.WaitGroup
	wg.Add(constants.NumberofWaitGroups)

	// Start the watchdog in its own goroutine
	go func() {
		defer wg.Done()
		log.Info("Starting watchdog goroutine")
		if err := wd.Start(ctx); err != nil {
			log.Error("Watchdog error", "error", err)
			// Signal the main goroutine to exit in case of watchdog error
			cancel()
		}
		log.Info("Watchdog goroutine completed")
	}()

	// Start the gRPC server in its own goroutine
	go func() {
		defer wg.Done()
		log.Info("Starting gRPC server")
		if err := server.RunServer(constants.DefaultSocketDir); err != nil {
			log.Error("gRPC server error", "error", err)
			// Signal the main goroutine to exit in case of server error
			cancel()
		}
		log.Info("gRPC server goroutine completed")
	}()

	// Wait for termination signal or context cancellation
	<-ctx.Done()
	log.Info("Context canceled, initiating shutdown")

	// Shutdown the gRPC server
	server.Shutdown()

	// Allow some time for cleanup operations
	shutdownTimer := time.NewTimer(5 * time.Second)
	defer shutdownTimer.Stop()

	log.Info("Waiting for goroutines to stop")
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info("All goroutines stopped successfully")
	case <-shutdownTimer.C:
		log.Warn("Shutdown timeout reached, forcing exit")
	}

	log.Info("Credentials Fetcher service stopped gracefully")
}
