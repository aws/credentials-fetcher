//go:build ignore

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/krb_utils"
)

func main() {
	// Get credentials from environment
	username := os.Getenv("KRB5_TEST_USERNAME")
	password := os.Getenv("KRB5_TEST_PASSWORD")
	domain := os.Getenv("KRB5_TEST_DOMAIN")

	if username == "" || password == "" || domain == "" {
		log.Fatal("Please set KRB5_TEST_USERNAME, KRB5_TEST_PASSWORD, and KRB5_TEST_DOMAIN")
	}

	principal := username + "@" + domain
	cachePath := "/tmp/krb5cc_renewal_test"

	fmt.Println("=== STEP 1: Create Initial Renewable Ticket ===")
	fmt.Printf("Principal: %s\n", principal)
	fmt.Printf("Cache Path: %s\n", cachePath)

	// Create initial ticket with renewable lifetime
	config := &krb_utils.KinitConfig{
		Principal:     principal,
		Password:      password,
		CCachePath:    cachePath,
		RenewableLife: 604800, // 7 days renewable
		Forwardable:   true,
		Verify:        true,
		Verbose:       true,
	}

	fmt.Println("\nGenerating initial ticket...")
	if err := krb_utils.GenerateKerberosTicket(config); err != nil {
		log.Fatalf("Failed to generate initial ticket: %v", err)
	}

	fmt.Println("\n✅ Initial ticket created successfully!")

	// Verify ticket
	fmt.Println("\n=== Verifying Initial Ticket ===")
	if err := krb_utils.VerifyTicket(cachePath); err != nil {
		log.Fatalf("Failed to verify initial ticket: %v", err)
	}

	// Wait a moment to simulate time passing
	fmt.Println("\nWaiting 2 seconds to simulate time passing...")
	time.Sleep(2 * time.Second)

	// Now test renewal
	fmt.Println("\n=== STEP 2: Renew Ticket (No Password Required) ===")

	renewConfig := &krb_utils.KinitConfig{
		CCachePath:  cachePath,
		RenewTicket: true, // ← This enables renewal mode
		Verify:      true,
		Verbose:     true,
	}

	fmt.Println("Renewing ticket without password...")
	if err := krb_utils.GenerateKerberosTicket(renewConfig); err != nil {
		log.Fatalf("Failed to renew ticket: %v", err)
	}

	fmt.Println("\n✅ Ticket renewed successfully!")

	// Verify renewed ticket
	fmt.Println("\n=== Verifying Renewed Ticket ===")
	if err := krb_utils.VerifyTicket(cachePath); err != nil {
		log.Fatalf("Failed to verify renewed ticket: %v", err)
	}

	fmt.Println("\n🎉 SUCCESS! Ticket renewal works correctly!")
	fmt.Println("\nCleanup: Removing test cache file...")
	os.Remove(cachePath)
}
