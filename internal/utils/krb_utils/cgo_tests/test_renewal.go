package main

import (
	"fmt"
	"os"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/krb_utils"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "create":
		createTicket()
	case "renew":
		renewTicket()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: test_renewal_program <command> [args]

Commands:
  create <principal> <password> <cache_path>
      Create a new Kerberos ticket with KDC default lifetime and renewable lifetime
      Example: test_renewal_program create user@REALM.COM password123 /tmp/krb5cc 86400

  renew <cache_path>
      Renew an existing ticket (like kinit -R)
      Example: test_renewal_program renew /tmp/krb5cc

  help
      Show this help message
`)
}

func createTicket() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "Error: create command requires 3 arguments\n\n")
		printUsage()
		os.Exit(1)
	}

	principal := os.Args[2]
	password := os.Args[3]
	cachePath := os.Args[4]

	fmt.Printf("Creating ticket for %s...\n", principal)
	fmt.Printf("  Cache path: %s\n", cachePath)
	fmt.Printf("  Using KDC default lifetime with 7-day renewable lifetime\n")

	config := &krb_utils.KinitConfig{
		Principal:     principal,
		Password:      password,
		CCachePath:    cachePath,
		Forwardable:   false,  // Not forwardable
		Lifetime:      0,      // 0 = use KDC default
		RenewableLife: 604800, // 7 days = 604800 seconds
		Verify:        true,
		Verbose:       true,
	}

	err := krb_utils.GenerateKerberosTicket(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating ticket: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Ticket created successfully!")
}

func renewTicket() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Error: renew command requires 1 argument\n\n")
		printUsage()
		os.Exit(1)
	}

	cachePath := os.Args[2]

	fmt.Printf("Renewing ticket at %s...\n", cachePath)

	config := &krb_utils.KinitConfig{
		CCachePath:  cachePath,
		RenewTicket: true,
		Verify:      true,
		Verbose:     true,
	}

	err := krb_utils.GenerateKerberosTicket(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error renewing ticket: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Ticket renewed successfully!")
}
