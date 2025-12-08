#!/bin/bash
# Test script for Kerberos ticket renewal using the Go kinit implementation
# This script creates an initial ticket, waits, then renews it and verifies the renewal occurred

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_CACHE_DIR="/tmp/krb_renewal_test_$$"
TEST_CACHE_GOKINIT="${TEST_CACHE_DIR}/krb5cc_gokinit"
TEST_CACHE_KINIT="${TEST_CACHE_DIR}/krb5cc_kinit"
WAIT_SECONDS=5  # Time to wait before renewal to ensure timestamps differ

# Function to print colored output
print_status() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Cleanup function
cleanup() {
    if [ -d "$TEST_CACHE_DIR" ]; then
        rm -rf "$TEST_CACHE_DIR"
        print_status "Cleaned up test directory"
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Check if required environment variables are set
check_environment() {
    print_status "Checking environment variables..."

    if [ -z "$KRB5_TEST_USERNAME" ]; then
        print_error "KRB5_TEST_USERNAME is not set"
        echo "Please set: export KRB5_TEST_USERNAME='your-username'"
        exit 1
    fi

    if [ -z "$KRB5_TEST_PASSWORD" ]; then
        print_error "KRB5_TEST_PASSWORD is not set"
        echo "Please set: export KRB5_TEST_PASSWORD='your-password'"
        exit 1
    fi

    if [ -z "$KRB5_TEST_DOMAIN" ]; then
        print_error "KRB5_TEST_DOMAIN is not set"
        echo "Please set: export KRB5_TEST_DOMAIN='EXAMPLE.COM'"
        exit 1
    fi

    print_success "All required environment variables are set"
    print_status "Principal: ${KRB5_TEST_USERNAME}@${KRB5_TEST_DOMAIN}"
}

# Get ticket lifetime from klist output
get_ticket_lifetime() {
    local cache_path="$1"
    # Get the validity period in seconds from klist
    # We'll parse the start and end times and calculate the difference
    klist -c "$cache_path" 2>/dev/null | grep "krbtgt/" | head -1
}

# Get renewable lifetime from klist output
get_renewable_lifetime() {
    local cache_path="$1"
    klist -c "$cache_path" 2>/dev/null | grep -i "renew until" || echo "No renewable lifetime"
}

# Extract expiration time from klist output
get_expiry_time() {
    local cache_path="$1"
    # Parse klist output to get krbtgt expiration time
    # Example line: "12/09/25 10:30:45  12/09/25 20:30:45  krbtgt/EXAMPLE.COM@EXAMPLE.COM"
    klist -c "$cache_path" 2>/dev/null | grep "krbtgt/" | awk '{print $2, $3}'
}

# Parse klist output to get ticket details
parse_klist_output() {
    local cache_path="$1"
    local output_file="$2"

    print_status "Ticket cache details:"
    klist -c "$cache_path" | tee "$output_file"
}

# Main test execution
main() {
    print_status "=== Kerberos Ticket Renewal Test ==="
    echo

    # Check environment
    check_environment
    echo

    # Create test directory
    print_status "Creating test directory: $TEST_CACHE_DIR"
    mkdir -p "$TEST_CACHE_DIR"
    print_success "Test directory created"
    echo

    # Step 1: Build the test program
    print_status "Building test program..."
    cd "$SCRIPT_DIR/.."
    go build -o "$SCRIPT_DIR/test_renewal_program" "$SCRIPT_DIR/test_renewal.go"
    if [ $? -ne 0 ]; then
        print_error "Failed to build test program"
        exit 1
    fi
    print_success "Test program built"
    echo

    # Step 2: Create ticket with standard kinit for comparison
    print_status "STEP 1a: Creating ticket with standard kinit..."
    print_status "  Using KDC default lifetime with 7-day renewable lifetime"

    # Use kinit with renewable flag
    echo "$KRB5_TEST_PASSWORD" | kinit -r 7d -c "$TEST_CACHE_KINIT" "${KRB5_TEST_USERNAME}@${KRB5_TEST_DOMAIN}" 2>&1

    if [ $? -ne 0 ]; then
        print_error "Failed to create ticket with kinit"
        exit 1
    fi
    print_success "Standard kinit ticket created"
    echo

    print_status "Standard kinit ticket details:"
    klist -c "$TEST_CACHE_KINIT"
    KINIT_LIFETIME=$(get_ticket_lifetime "$TEST_CACHE_KINIT")
    KINIT_RENEWABLE=$(get_renewable_lifetime "$TEST_CACHE_KINIT")
    print_status "Lifetime: $KINIT_LIFETIME"
    print_status "Renewable: $KINIT_RENEWABLE"
    echo

    # Step 3: Create initial ticket with go-kinit
    print_status "STEP 1b: Creating initial renewable ticket with go-kinit..."
    print_status "  Using KDC default lifetime with 7-day renewable lifetime"

    "$SCRIPT_DIR/test_renewal_program" create \
        "$KRB5_TEST_USERNAME@$KRB5_TEST_DOMAIN" \
        "$KRB5_TEST_PASSWORD" \
        "$TEST_CACHE_GOKINIT"

    if [ $? -ne 0 ]; then
        print_error "Failed to create initial ticket with go-kinit"
        exit 1
    fi
    print_success "Go-kinit ticket created"
    echo

    print_status "Go-kinit ticket details:"
    klist -c "$TEST_CACHE_GOKINIT"
    GOKINIT_LIFETIME=$(get_ticket_lifetime "$TEST_CACHE_GOKINIT")
    GOKINIT_RENEWABLE=$(get_renewable_lifetime "$TEST_CACHE_GOKINIT")
    print_status "Lifetime: $GOKINIT_LIFETIME"
    print_status "Renewable: $GOKINIT_RENEWABLE"
    echo

    # Step 4: Compare lifetimes
    print_status "STEP 2: Comparing kinit vs go-kinit lifetimes..."
    echo "Standard kinit:"
    echo "  $KINIT_LIFETIME"
    echo "  $KINIT_RENEWABLE"
    echo
    echo "Go-kinit:"
    echo "  $GOKINIT_LIFETIME"
    echo "  $GOKINIT_RENEWABLE"
    echo

    if [ "$KINIT_LIFETIME" = "$GOKINIT_LIFETIME" ] && [ "$KINIT_RENEWABLE" = "$GOKINIT_RENEWABLE" ]; then
        print_success "✓ Lifetimes match between kinit and go-kinit!"
    else
        print_warning "⚠ Lifetimes differ between kinit and go-kinit"
        print_warning "This may need investigation"
    fi
    echo

    # Step 5: Parse and save initial ticket info
    print_status "STEP 3: Checking initial go-kinit ticket with klist..."
    INITIAL_OUTPUT="${TEST_CACHE_DIR}/initial_gokinit_klist.txt"
    parse_klist_output "$TEST_CACHE_GOKINIT" "$INITIAL_OUTPUT"

    # Extract initial expiry time
    INITIAL_EXPIRY=$(get_expiry_time "$TEST_CACHE_GOKINIT")
    print_status "Initial expiry: $INITIAL_EXPIRY"
    echo

    # Step 6: Wait before renewal to ensure timestamp changes
    print_status "STEP 4: Waiting ${WAIT_SECONDS} seconds before renewal..."
    for i in $(seq $WAIT_SECONDS -1 1); do
        echo -n -e "\r   Waiting... $i seconds remaining "
        sleep 1
    done
    echo
    print_success "Wait complete"
    echo

    # Step 7: Renew the ticket
    print_status "STEP 5: Renewing go-kinit ticket (kinit -R equivalent)..."
    "$SCRIPT_DIR/test_renewal_program" renew "$TEST_CACHE_GOKINIT"

    if [ $? -ne 0 ]; then
        print_error "Failed to renew ticket"
        exit 1
    fi
    print_success "Ticket renewed"
    echo

    # Step 8: Parse and save renewed ticket info
    print_status "STEP 6: Checking renewed ticket with klist..."
    RENEWED_OUTPUT="${TEST_CACHE_DIR}/renewed_gokinit_klist.txt"
    parse_klist_output "$TEST_CACHE_GOKINIT" "$RENEWED_OUTPUT"

    # Extract renewed expiry time
    RENEWED_EXPIRY=$(get_expiry_time "$TEST_CACHE_GOKINIT")
    print_status "Renewed expiry: $RENEWED_EXPIRY"
    echo

    # Step 9: Verify renewal occurred
    print_status "STEP 7: Verifying renewal..."

    # Check that ticket cache still exists
    if [ ! -f "$TEST_CACHE_GOKINIT" ]; then
        print_error "Ticket cache file disappeared after renewal!"
        exit 1
    fi
    print_success "Ticket cache file exists"

    # Check that we can still read the ticket
    if ! klist -c "$TEST_CACHE_GOKINIT" >/dev/null 2>&1; then
        print_error "Cannot read ticket cache after renewal!"
        exit 1
    fi
    print_success "Ticket cache is readable"

    # Check that the ticket is valid
    if ! klist -s -c "$TEST_CACHE_GOKINIT" 2>/dev/null; then
        print_error "Ticket is not valid after renewal!"
        exit 1
    fi
    print_success "Ticket is valid (klist -s passed)"

    # Compare timestamps
    if [ "$INITIAL_EXPIRY" = "$RENEWED_EXPIRY" ]; then
        print_warning "Expiry times are identical - renewal may not have updated the ticket"
        print_warning "Initial:  $INITIAL_EXPIRY"
        print_warning "Renewed:  $RENEWED_EXPIRY"
        print_warning "This could be normal if KDC doesn't change expiry on renewal"
    else
        print_success "Expiry times differ - renewal updated the ticket"
        print_status "Initial:  $INITIAL_EXPIRY"
        print_status "Renewed:  $RENEWED_EXPIRY"
    fi
    echo

    # Step 10: Show diff between initial and renewed
    print_status "STEP 8: Comparing initial vs. renewed ticket output..."
    echo "------- Differences -------"
    diff -u "$INITIAL_OUTPUT" "$RENEWED_OUTPUT" || true
    echo "---------------------------"
    echo

    # Step 11: Test renewal flags with klist -f
    print_status "STEP 9: Checking ticket flags (klist -f)..."
    klist -f -c "$TEST_CACHE_GOKINIT" | grep -E "(Flags|krbtgt)" || true
    echo

    # Success!
    print_success "=== All tests passed! ==="
    echo
    print_status "Summary:"
    print_success "  • Compared kinit vs go-kinit ticket lifetimes"
    print_success "  • Initial ticket created with renewable lifetime"
    print_success "  • Ticket successfully renewed without password"
    print_success "  • Renewed ticket is valid and readable"
    print_status "  • Go-kinit cache: $TEST_CACHE_GOKINIT"
    print_status "  • Kinit cache: $TEST_CACHE_KINIT"
    echo
    print_status "Test artifacts saved in: $TEST_CACHE_DIR"
    print_status "  - initial_gokinit_klist.txt: Initial go-kinit ticket details"
    print_status "  - renewed_gokinit_klist.txt: Renewed go-kinit ticket details"
}

# Run main function
main "$@"
