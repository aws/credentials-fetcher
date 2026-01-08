#!/bin/bash

# Open Source Build Script for credentials-fetcher

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Simple logging
log() { echo "$(date +'%H:%M:%S') $1"; }
error() { echo "$(date +'%H:%M:%S') ERROR: $1" >&2; exit 1; }

# Load configuration from build.conf if it exists
load_config() {
    local config_file="${SCRIPT_DIR}/config/build.conf"
    if [[ -f "${config_file}" ]]; then
        log "Loading configuration from ${config_file}"
        source "${config_file}"
    fi
}

# Load configuration first
load_config

# Default values (can be overridden by environment variables or build.conf)
VERSION="${VERSION:-2.0.0}"
BIN_DIR="${BIN_DIR:-${SCRIPT_DIR}/bin}"
BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/build}"
ENABLE_DEBUGGING="${ENABLE_DEBUGGING:-0}"
CODE_COVERAGE="${CODE_COVERAGE:-0}"
BUILD_FLAGS="${BUILD_FLAGS:--trimpath -buildvcs=0}"

# Convert relative paths to absolute paths
if [[ "${BIN_DIR}" != /* ]]; then
    BIN_DIR="${SCRIPT_DIR}/${BIN_DIR}"
fi
if [[ "${BUILD_DIR}" != /* ]]; then
    BUILD_DIR="${SCRIPT_DIR}/${BUILD_DIR}"
fi

# Go build flags - combines BUILD_FLAGS with linker flags
# BUILD_FLAGS: -trimpath (remove paths) + -buildvcs=0 (disable VCS info) 
# ldflags: -s (strip symbol table) + -w (strip debug info) + -X (set version in constants package)
GO_FLAGS="${BUILD_FLAGS:--trimpath -buildvcs=0} -ldflags=\"-s -w -X golang.a2z.com/CredentialsFetcherV2/constants.Version=${VERSION}\""

if [[ "${ENABLE_DEBUGGING}" == "1" ]]; then
    GO_FLAGS="${GO_FLAGS} -gcflags=\"all=-N -l\""
fi

if [[ "${CODE_COVERAGE}" == "1" ]]; then
    GO_FLAGS="${GO_FLAGS} -cover"
fi

# Usage 
usage() {
    cat << EOF
Usage: $0 [TARGET]

Open Source Build Script for credentials-fetcher (matches Brazil build workflow)

TARGETS:
  all                 Run complete pipeline: test and build
  build               Build binary only (default)
  build-only          Build binary only
  test                Run tests
  build-clean         Clean build artifacts
  check_help          Show binary help
  clean               Clean all artifacts

ENVIRONMENT VARIABLES:
  VERSION             Version to embed (default: ${VERSION})
  ENABLE_DEBUGGING    Enable debug symbols (0/1, default: ${ENABLE_DEBUGGING})
  CODE_COVERAGE       Enable code coverage (0/1, default: ${CODE_COVERAGE})
  BIN_DIR             Binary output directory (default: opensource/bin)
  BUILD_DIR           Build artifacts directory (default: opensource/build)

EOF
}

# Clean build artifacts 
build_clean() {
    log "Cleaning build directory..."
    rm -rf "${BUILD_DIR}/gopath"
    mkdir -p "${BUILD_DIR}"
    log "Build directory cleaned"
}

# Clean all artifacts
clean() {
    log "Cleaning all build artifacts..."
    rm -rf "${BUILD_DIR}" "${BIN_DIR}"
    log "All artifacts cleaned"
}

# Build binary 
build() {
    log "Building credentials-fetcherd binary..."
    
    mkdir -p "${BIN_DIR}"
    cd "${PROJECT_ROOT}"
    
    # Use eval to properly handle the quoted flags
    eval "go build ${GO_FLAGS} -o ${BIN_DIR}/credentials-fetcherd ./cmd/credentials-fetcher/main.go"
    
    if [[ -x "${BIN_DIR}/credentials-fetcherd" ]]; then
        log "Binary built successfully: ${BIN_DIR}/credentials-fetcherd"
    else
        error "Failed to build binary"
    fi
}

# Run tests
test() {
    log "Running Go tests..."
    cd "${PROJECT_ROOT}"
    
    local test_flags="-v"
    if [[ "${CODE_COVERAGE}" == "1" ]]; then
        test_flags="${test_flags} -cover"
    fi
    
    if go test ${test_flags} ./...; then
        log "All tests passed"
    else
        error "Tests failed"
    fi
}

# Show binary help (matching Makefile check_help)
check_help() {
    if [[ ! -x "${BIN_DIR}/credentials-fetcherd" ]]; then
        error "Binary not found. Run 'build' first."
    fi
    
    "${BIN_DIR}/credentials-fetcherd" --help
}

# Build-only target 
build_only() {
    build
}

# All target - complete pipeline
all() {
    test
    build
}

# Parse arguments
TARGET="${1:-build}"

case "${TARGET}" in
    -h|--help|help)
        usage
        exit 0
        ;;
    all)
        log "Running all target (test + build)"
        all
        ;;
    build-only)
        log "Running build-only target (build)"
        build_only
        ;;
    build)
        build
        ;;
    test)
        test
        ;;
    build-clean)
        build_clean
        ;;
    check_help)
        check_help
        ;;
    clean)
        clean
        ;;
    *)
        error "Unknown target: ${TARGET}. Use --help for available targets."
        ;;
esac

log "Target '${TARGET}' completed successfully!"