# Kerberos Utilities (krb_utils)

This package provides utilities for working with Kerberos authentication in Go, including a Go implementation of `kinit` using CGO.

## Features

- **Native Kerberos Ticket Generation**: Uses MIT Kerberos C libraries via CGO (no need to shell out to `kinit`)
- **Custom Cache Path Support**: Specify where to store Kerberos tickets
- **Configurable Options**: Forwardable tickets, lifetime, renewable options
- **Ticket Validation**: Built-in validation using `klist`

## Usage

### Basic Example

```go
import "golang.a2z.com/CredentialsFetcherV2/internal/utils/krb_utils"

// Create a simple config
config := krb_utils.NewKinitConfigWithCache(
    "user@EXAMPLE.COM",
    "password",
    "/tmp/krb5cc_myapp",
)

// Generate the Kerberos ticket
err := krb_utils.GenerateKerberosTicket(config)
if err != nil {
    log.Fatal(err)
}
```

### Custom Cache Path

```go
// Specify a custom cache path
cachePath := "/tmp/my_krb5cc"
config := krb_utils.NewKinitConfigWithCache(
    "user@EXAMPLE.COM",
    "password",
    cachePath,
)
err := krb_utils.GenerateKerberosTicket(config)
```

### Advanced Configuration

```go
config := &krb_utils.KinitConfig{
    Principal:   "user@EXAMPLE.COM",
    Password:    "password",
    CCachePath:  "/tmp/krb5cc_custom",
    Forwardable: true,
    Verify:      true,
    Verbose:     true,
err := krb_utils.GenerateKerberosTicket(config)
```

### Renewing an Existing Ticket (like `kinit -R`)

You can renew an existing Kerberos ticket without providing credentials:

```go
// Renew an existing ticket without needing the password
config := &krb_utils.KinitConfig{
    CCachePath:  "/tmp/krb5cc_1000",
    RenewTicket: true,  // ← Enables renewal mode
    Verify:      true,
    Verbose:     true,
}

err := krb_utils.GenerateKerberosTicket(config)
if err != nil {
    log.Fatal(err)
}
```

**Requirements for ticket renewal:**
- The ticket must have been created with a renewable lifetime (`RenewableLife > 0`)
- The ticket must not be expired
- The ticket must still be within its renewable period

## Testing

### Running Tests with Coverage Script

The package includes a convenient script to run tests and generate coverage reports:

```bash
cd internal/utils/krb_utils

# Show all available options
./test_coverage.sh --help

# Run unit tests only (no credentials required)
./test_coverage.sh --unit

# Generate coverage excluding CGO wrapper (~79%)
./test_coverage.sh --coverage-no-cgo

# Generate coverage with integration test (requires credentials)
export KRB5_TEST_USERNAME='your-username'
export KRB5_TEST_PASSWORD='your-password'
export KRB5_TEST_DOMAIN='EXAMPLE.COM'
./test_coverage.sh --coverage-full-no-cgo

# View HTML coverage report
./test_coverage.sh --coverage-no-cgo --html
```

### Manual Testing

#### Running the Integration Test

The `TestGenerateKerberosTicket` test performs a real Kerberos authentication and validates the ticket. By default, this test is **skipped** to avoid committing passwords to git.

To run the test with your own credentials:

```bash
# Set your Kerberos credentials
export KRB5_TEST_USERNAME='your-username'
export KRB5_TEST_PASSWORD='your-password'
export KRB5_TEST_DOMAIN='EXAMPLE.COM'
export KRB5_TEST_CACHE_PATH='/tmp/my_custom_cache'  # Optional, defaults to /tmp/krb5cc_test_<username>

# Run the test
cd internal/utils/krb_utils
go test -v -run TestGenerateKerberosTicket
```

**Note**: If `KRB5_TEST_CACHE_PATH` is not set, the test will default to `/tmp/krb5cc_test_<username>`.

The test will:
1. Generate a Kerberos ticket for your user (`$KRB5_TEST_USERNAME@$KRB5_TEST_DOMAIN`)
2. Verify the ticket cache file was created
3. Run `klist` to display ticket information
4. Validate ticket content (principal, cache path, TGT)
5. Check ticket validity with `klist -s`
6. Display ticket flags with `klist -f`

**Security Note**: Never commit the `KRB5_TEST_USERNAME`, `KRB5_TEST_PASSWORD`, `KRB5_TEST_DOMAIN`, or `KRB5_TEST_CACHE_PATH` environment variables or hardcode credentials in the test files.

#### Running Unit Tests Only

To run only the unit tests (which don't require credentials):

```bash
go test -v -run TestNewKinitConfig
go test -v -run TestGenerateKerberosTicketValidation
```

## Implementation Details

This package uses **CGO** to call the native MIT Kerberos C libraries (`libkrb5`), providing a Go interface to Kerberos authentication.

### Architecture

The package uses a **dependency injection** architecture with four layers for improved testability and maintainability:

```
┌─────────────────────────────────────┐
│  GenerateKerberosTicket()           │  ← Public API
│  (go_kinit.go)                      │    Entry point for library users
└─────────────┬───────────────────────┘
              │
              ↓
┌─────────────────────────────────────┐
│  Krb5Client Interface               │  ← High-level business logic
│  (krb5_client.go)                   │    • Input validation
│                                     │    • Error handling & formatting
│  NewKrb5Client(wrapper)             │    • Verbose output
└─────────────┬───────────────────────┘    • Ticket verification
              │
              ↓
┌─────────────────────────────────────┐
│  Krb5Wrapper Interface              │  ← Low-level operations
│  • InitContext()                    │    (fully mockable!)
│  • ParseName()                      │
│  • GetInitCredsPassword()           │    Each CGO call wrapped
│  • ResolveCache()                   │    as a separate method
│  • MkdirAll(), Chmod(), Stat()      │
│  • ... and more                     │
└─────────────┬───────────────────────┘
              │
              ↓
┌─────────────────────────────────────┐
│  cgoKrb5Wrapper                     │  ← CGO implementation
│  (krb5_cgo_wrapper.go)              │    (calls C libraries)
│                                     │
│  /* #cgo LDFLAGS: -lkrb5 */         │    Direct calls to:
│  /* #include <krb5.h> */            │    • krb5_init_context
│                                     │    • krb5_parse_name
│                                     │    • krb5_get_init_creds_password
│                                     │    • krb5_cc_store_cred
│                                     │    • etc.
└─────────────────────────────────────┘
```

### Layer Responsibilities

**Layer 1: Public API (`go_kinit.go`)**
- Simple entry points: `GenerateKerberosTicket(config)`
- Helper constructors: `NewKinitConfig()`, `NewKinitConfigWithCache()`
- Uses default implementations (can be overridden for testing)

**Layer 2: Business Logic (`krb5_client.go`, `Krb5Client` interface)**
- Input validation (required fields, format checking)
- Error message formatting and wrapping
- Configuration option application
- Verbose output and user feedback
- **100% testable** - no direct CGO calls

**Layer 3: Low-Level Operations (`krb5_interface.go`, `Krb5Wrapper` interface)**
- Interface definition for all krb5 operations
- Each C function call has a corresponding Go method
- File system operations (MkdirAll, Chmod, Stat)
- Utility operations (RunKlist)

**Layer 4: CGO Implementation (`krb5_cgo_wrapper.go`, `cgoKrb5Wrapper`)**
- Direct calls to MIT Kerberos C library functions
- C memory management (malloc, free)
- Type conversions between Go and C
- Unsafe pointer operations

### Testing Strategy

**Unit Tests** (krb5_client_test.go):
- Mock `Krb5Wrapper` implementation
- Test all error paths individually
- Test configuration options
- **No CGO required** - fast, reliable tests

**Integration Test** (go_kinit_test.go):
- Uses real CGO wrapper
- Tests actual Kerberos authentication
- Requires real credentials (via environment variables)
- Validates with `klist` command

### Test Coverage

**Coverage: 79.0%** (business logic only, excluding CGO wrapper)

The CGO wrapper is intentionally excluded from coverage metrics because:
- It's a **thin shim** over C library calls with minimal logic
- Unit tests use **mocks** for fast, reliable testing
- Integration tests cover the full CGO stack with real Kerberos
- This is a common pattern in Go projects that use CGO

**Coverage Options:**

```bash
# Business logic only (recommended for tracking code quality)
./test_coverage.sh --coverage-no-cgo
# Result: ~79.0%

# Full coverage including CGO wrapper (for completeness)
./test_coverage.sh --coverage
# Result: ~55.6% (without integration) or ~77.1% (with integration)
```

**What's tested:**
- ✅ All business logic error paths
- ✅ Configuration validation
- ✅ Kerberos ticket generation (unit + integration)
- ✅ Ticket parsing utilities
- ✅ Credential spec processing
- ✅ Date parsing with multiple formats

### CGO Directives

The implementation uses CGO to interact with the system's Kerberos libraries:

```go
/*
#cgo LDFLAGS: -lkrb5
#include <krb5.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"
```

- **`#cgo LDFLAGS: -lkrb5`** - Links against the system's `libkrb5` shared library
- **`#include <krb5.h>`** - Includes the MIT Kerberos C headers
- **`import "C"`** - Special Go import that enables CGO

### System Requirements

This package requires the MIT Kerberos development libraries to be installed on the system:

- **Amazon Linux / RHEL / CentOS**: `krb5-devel` or `krb5-libs`
- **Ubuntu / Debian**: `libkrb5-dev`
- **macOS**: Kerberos is included by default

At runtime, only `libkrb5` shared library is required (not the development headers).

### Benefits

- **No Shelling Out**: Direct library calls instead of executing `kinit` command
- **Better Error Handling**: Get structured errors from the C library
- **Password Security**: Passwords are passed directly to the library, not via command-line arguments
- **Cross-Platform**: Works consistently across different operating systems
- **Highly Testable**: Dependency injection architecture allows comprehensive unit testing
  - Mock individual CGO calls for edge case testing
  - Test error paths without real Kerberos infrastructure
  - Fast unit tests without integration dependencies
- **Maintainable**: Clear separation of concerns across layers

## Renewal vs. Initial Authentication

The package supports two modes of operation:

**1. Initial Authentication** (default - requires credentials):
- Creates a new Kerberos ticket from scratch
- Requires: `Principal`, `Password`, `CCachePath`
- Sets ticket properties: forwardable, lifetime, renewable, etc.

**2. Ticket Renewal** (`RenewTicket: true` - no credentials needed):
- Renews an existing renewable ticket
- Only requires: `CCachePath` and `RenewTicket: true`
- No password needed (uses the existing ticket to authenticate)
- Equivalent to `kinit -R` command

Use renewal mode for long-running services that need to periodically refresh their tickets without storing passwords.- **krb5_interface.go** - Interface definitions for all layers
- **krb5_client.go** - High-level business logic implementation
- **krb5_cgo_wrapper.go** - CGO wrapper for MIT Kerberos C library
- **krb5_client_test.go** - Unit tests with mock wrapper
- **go_kinit_test.go** - Integration test with real credentials
- **krb_utils.go** - Utility functions for parsing klist output
- **test_coverage.sh** - Script for generating coverage reports
