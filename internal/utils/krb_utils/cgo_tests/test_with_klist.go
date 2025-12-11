//go:build ignore

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/krb_utils"
)

func showTicketInfo(path string) {
	cmd := exec.Command("klist", "-f", "-c", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("klist error: %v", err)
		return
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Valid") || strings.Contains(line, "Renew") ||
			strings.Contains(line, "Flags") || strings.Contains(line, "krbtgt") {
			fmt.Println(line)
		}
	}
}

func main() {
	// Get credentials from environment variables
	principal := os.Getenv("KRB5_TEST_USERNAME")
	password := os.Getenv("KRB5_TEST_PASSWORD")
	domain := os.Getenv("KRB5_TEST_DOMAIN")

	if principal == "" || password == "" || domain == "" {
		log.Fatal("Required environment variables not set:\n" +
			"  KRB5_TEST_USERNAME - Kerberos username\n" +
			"  KRB5_TEST_PASSWORD - Kerberos password\n" +
			"  KRB5_TEST_DOMAIN - Kerberos domain (e.g., EXAMPLE.COM)")
	}

	// Construct full principal if needed
	fullPrincipal := principal
	if !strings.Contains(principal, "@") {
		fullPrincipal = principal + "@" + domain
	}

	cachePath := "/tmp/krb5cc_renewal_demo"

	fmt.Println("=== Step 1: Create renewable ticket ===")
	config1 := &krb_utils.KinitConfig{
		Principal:     fullPrincipal,
		Password:      password,
		CCachePath:    cachePath,
		RenewableLife: 604800,
		Forwardable:   true,
	}
	if err := krb_utils.GenerateKerberosTicket(config1); err != nil {
		log.Fatalf("Failed: %v", err)
	}
	fmt.Println("✓ Initial ticket created\n")
	fmt.Println("Initial ticket info:")
	showTicketInfo(cachePath)

	time.Sleep(2 * time.Second)

	fmt.Println("\n=== Step 2: Renew ticket (no password) ===")
	config2 := &krb_utils.KinitConfig{
		CCachePath:  cachePath,
		RenewTicket: true,
	}
	if err := krb_utils.GenerateKerberosTicket(config2); err != nil {
		log.Fatalf("Failed: %v", err)
	}
	fmt.Println("✓ Ticket renewed\n")
	fmt.Println("Renewed ticket info:")
	showTicketInfo(cachePath)

	fmt.Println("\n🎉 Success!")
}
