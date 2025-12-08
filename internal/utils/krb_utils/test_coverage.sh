#!/bin/bash
# Test coverage script for krb_utils package
# Provides coverage reports with and without CGO wrapper

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --unit                Run unit tests only (no credentials required)"
    echo "  --integration         Run integration test (requires credentials)"
    echo "  --coverage            Generate coverage report (unit tests)"
    echo "  --coverage-no-cgo     Generate coverage excluding CGO wrapper (~79%)"
    echo "  --coverage-full       Generate coverage with integration test (~77%)"
    echo "  --coverage-full-no-cgo Generate coverage with integration, excluding CGO (~90%+)"
    echo "  --html                Open HTML coverage report in browser"
    echo "  --clean               Remove coverage files"
    echo "  --help                Show this help message"
    echo ""
    echo "Environment variables for integration test:"
    echo "  KRB5_TEST_USERNAME    - Your Kerberos username"
    echo "  KRB5_TEST_PASSWORD    - Your Kerberos password"
    echo "  KRB5_TEST_DOMAIN      - Your Kerberos domain (e.g., EXAMPLE.COM)"
    echo "  KRB5_TEST_CACHE_PATH  - Optional cache path (defaults to /tmp/krb5cc_test_<username>)"
    echo ""
    echo "Examples:"
    echo "  $0 --coverage-no-cgo              # Business logic coverage only"
    echo "  $0 --coverage-full-no-cgo --html  # Full coverage excluding CGO, with HTML report"
}

check_credentials() {
    if [ -z "$KRB5_TEST_USERNAME" ] || [ -z "$KRB5_TEST_PASSWORD" ] || [ -z "$KRB5_TEST_DOMAIN" ]; then
        echo -e "${RED}Error: Set KRB5_TEST_USERNAME, KRB5_TEST_PASSWORD, and KRB5_TEST_DOMAIN environment variables${NC}"
        exit 1
    fi
}

warn_credentials() {
    if [ -z "$KRB5_TEST_USERNAME" ] || [ -z "$KRB5_TEST_PASSWORD" ] || [ -z "$KRB5_TEST_DOMAIN" ]; then
        echo -e "${YELLOW}Warning: Integration test will be skipped. Set KRB5_TEST_* environment variables to include it.${NC}"
    fi
}

run_unit_tests() {
    echo -e "${BLUE}Running unit tests...${NC}"
    go test -v -run 'Test(NewKinitConfig|GenerateKerberosTicketValidation|Krb5Client|Parse|IsDateFormat|Validate|IsTicket|IsDomainless|ProcessCredential)'
}

run_integration_test() {
    check_credentials
    echo -e "${BLUE}Running integration test...${NC}"
    go test -v -run TestGenerateKerberosTicket
}

generate_coverage() {
    echo -e "${BLUE}Running tests and generating coverage...${NC}"
    warn_credentials
    go test -coverprofile=coverage.out
    echo -e "\n${GREEN}=== Coverage Report (including CGO wrapper) ===${NC}"
    go tool cover -func=coverage.out | tail -1
    echo -e "\n${YELLOW}To view HTML report: go tool cover -html=coverage.out${NC}"
}

generate_coverage_no_cgo() {
    echo -e "${BLUE}Running tests and generating coverage (excluding CGO wrapper)...${NC}"
    warn_credentials
    go test -coverprofile=coverage.out 2>&1 | grep -E "(PASS|FAIL|coverage:)"
    grep -v "krb5_cgo_wrapper.go" coverage.out > coverage_filtered.out
    echo -e "\n${GREEN}=== Business Logic Coverage (excluding CGO wrapper) ===${NC}"
    go tool cover -func=coverage_filtered.out | tail -1
    echo -e "\n${YELLOW}To view HTML report: go tool cover -html=coverage_filtered.out${NC}"
}

generate_coverage_full() {
    check_credentials
    echo -e "${BLUE}Running tests with integration and generating coverage...${NC}"
    go test -coverprofile=coverage.out
    echo -e "\n${GREEN}=== Full Coverage (with integration test) ===${NC}"
    go tool cover -func=coverage.out | tail -1
    echo -e "\n${YELLOW}To view HTML report: go tool cover -html=coverage.out${NC}"
}

generate_coverage_full_no_cgo() {
    check_credentials
    echo -e "${BLUE}Running tests with integration and generating coverage (excluding CGO)...${NC}"
    go test -coverprofile=coverage.out 2>&1 | grep -E "(PASS|FAIL|coverage:|Successfully acquired)"
    grep -v "krb5_cgo_wrapper.go" coverage.out > coverage_filtered.out
    echo -e "\n${GREEN}=== Business Logic Coverage (with integration, excluding CGO) ===${NC}"
    go tool cover -func=coverage_filtered.out | tail -1
    echo -e "\n${YELLOW}To view HTML report: go tool cover -html=coverage_filtered.out${NC}"
}

open_html() {
    if [ -f "coverage_filtered.out" ]; then
        echo -e "${BLUE}Opening filtered coverage report in browser...${NC}"
        go tool cover -html=coverage_filtered.out
    elif [ -f "coverage.out" ]; then
        echo -e "${BLUE}Opening coverage report in browser...${NC}"
        go tool cover -html=coverage.out
    else
        echo -e "${RED}Error: No coverage file found. Run a coverage command first.${NC}"
        exit 1
    fi
}

clean_files() {
    echo -e "${BLUE}Cleaning coverage files...${NC}"
    rm -f coverage.out coverage_filtered.out
    echo -e "${GREEN}Coverage files removed.${NC}"
}

# Parse arguments
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --unit)
            run_unit_tests
            shift
            ;;
        --integration)
            run_integration_test
            shift
            ;;
        --coverage)
            generate_coverage
            shift
            ;;
        --coverage-no-cgo)
            generate_coverage_no_cgo
            shift
            ;;
        --coverage-full)
            generate_coverage_full
            shift
            ;;
        --coverage-full-no-cgo)
            generate_coverage_full_no_cgo
            shift
            ;;
        --html)
            open_html
            shift
            ;;
        --clean)
            clean_files
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done
