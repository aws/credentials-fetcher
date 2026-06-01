package debug_utils

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

// Debug error injection simulation targets.
// Set CF_DEBUG_SIMULATE_ERROR to one of these values with LOG_LEVEL=debug to trigger.
const (
	SimulateSetupKerberosFile    = "setup_kerberos_file"
	SimulateCreateTicketGMSA     = "create_ticket_gmsa"
	SimulateGetDistinguishedName = "get_distinguished_name"

	envDebugSimulateError    = "CF_DEBUG_SIMULATE_ERROR"
	maxDebugErrorSimulations = 3
)

// debugErrorCount tracks how many times SimulateDebugError has been invoked.
var debugErrorCount atomic.Int32

// SimulateDebugError returns a simulated error when debug error injection is
// enabled for the given operation. It requires both LOG_LEVEL=debug and
// CF_DEBUG_SIMULATE_ERROR=<operation> to be set. Returns nil after being
// invoked more than 3 times to prevent infinite error loops.
func SimulateDebugError(operation string) error {
	if os.Getenv("LOG_LEVEL") != "debug" {
		return nil
	}

	target := strings.TrimSpace(os.Getenv(envDebugSimulateError))
	if target == "" || target != operation {
		return nil
	}

	log := logger.GetInstance()

	if debugErrorCount.Add(1) > maxDebugErrorSimulations {
		log.Warn("DEBUG ERROR INJECTION: invocation limit reached, skipping",
			"operation", operation, "limit", maxDebugErrorSimulations)
		return nil
	}

	log.Warn("DEBUG ERROR INJECTION: simulating error",
		"operation", operation)
	return fmt.Errorf("simulated debug error in %s", operation)
}

// ResetDebugErrorCount resets the invocation counter (for testing).
func ResetDebugErrorCount() {
	debugErrorCount.Store(0)
}
