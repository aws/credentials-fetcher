#!/bin/bash

# Open Source Build Script for credentials-fetcher

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default values 
VERSION="${VERSION:-2.0.0}"
BIN_DIR="${BIN_DIR:-${SCRIPT_DIR}/bin}"
BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/build}"
ENABLE_DEBUGGING="${ENABLE_DEBUGGING:-0}"
CODE_COVERAGE="${CODE_COVERAGE:-0}"

# Detect OS 
OS="$(uname -s)"
if [[ "${OS}" == "Linux" ]]; then
    OS_ID="$(cat /etc/os-release 2>/dev/null | grep ^ID= | cut -d'=' -f2 | tr -d '"' || echo "unknown")"
else
    OS_ID="${OS}"
fi

# Configuration 
CF_KRB_DIR="${CF_KRB_DIR:-/var/credentials-fetcher/krbdir}"
CF_UNIX_DOMAIN_SOCKET_DIR="${CF_UNIX_DOMAIN_SOCKET_DIR:-/var/credentials-fetcher/socket}"
CF_LOGGING_DIR="${CF_LOGGING_DIR:-/var/credentials-fetcher/logging}"

# Go build flags 
GO_FLAGS="-trimpath -buildvcs=0 -ldflags=\"-s -w -X main.Version=${VERSION}\""

if [[ "${ENABLE_DEBUGGING}" == "1" ]]; then
    GO_FLAGS="${GO_FLAGS} -gcflags=\"all=-N -l\""
fi

if [[ "${CODE_COVERAGE}" == "1" ]]; then
    GO_FLAGS="${GO_FLAGS} -cover"
fi

# Simple logging
log() { echo "$(date +'%H:%M:%S') $1"; }
error() { echo "$(date +'%H:%M:%S') ERROR: $1" >&2; exit 1; }

# Usage 
usage() {
    cat << EOF
Usage: $0 [TARGET]

Open Source Build Script for credentials-fetcher (matches Brazil build workflow)

TARGETS:
  all                 Run complete pipeline: security-check, lint-check, test, and build
  build-only          Run security-check, lint-check, and build (default, matches BGO_DEFAULT_TARGET)
  release-strict      Run security-check, lint-check, and build (matches BGO_RELEASE_TARGET)
  build               Build binary only
  security-check      Run security scan (gosec)
  lint-check          Run linting (golangci-lint)
  test                Run tests
  build-clean         Clean build artifacts
  cf-create-service   Create systemd service file
  cf-install          Install binary and service (requires sudo)
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

# Security check 
security_check() {
    log "Running security check..."
    
    if ! command -v gosec >/dev/null 2>&1; then
        error "gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"
    fi
    
    mkdir -p "${BUILD_DIR}/private/gosec"
    
    cd "${PROJECT_ROOT}"
    if gosec -exclude-generated -exclude="**/proto/*.pb.go" -fmt=json -out="${BUILD_DIR}/private/gosec/results.json" ./...; then
        log "Security check passed"
    else
        if [[ -f "${BUILD_DIR}/private/gosec/results.json" ]]; then
            cat "${BUILD_DIR}/private/gosec/results.json"
            echo
            echo "GoSec returned with error. Fix the errors above or add the comment '/* #nosec */' to ignore the affected line."
        fi
        exit 1
    fi
}

# Lint check 
lint_check() {
    log "Running golangci-lint"
    
    if ! command -v golangci-lint >/dev/null 2>&1; then
        error "golangci-lint not found. Install with: go install https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh"
    fi
    
    cd "${PROJECT_ROOT}"
    if golangci-lint run ./...; then
        log "Linting passed"
    else
        exit 1
    fi
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

# Create systemd service file 
cf_create_service() {
    log "Creating systemd service file..."
    
    mkdir -p "${BUILD_DIR}"
    
    cat > "${BUILD_DIR}/credentials-fetcher.service" << EOF
[Unit]
Description=credentials-fetcher systemd service unit file.

[Service]
StandardError=journal
StandardOutput=journal
StandardInput=null
ExecStartPre=/bin/mkdir -p ${CF_KRB_DIR} ${CF_UNIX_DOMAIN_SOCKET_DIR} ${CF_LOGGING_DIR}
EOF

    # OS-specific configuration (matching Makefile logic)
    if [[ "${OS_ID}" == "amzn" ]]; then
        cat >> "${BUILD_DIR}/credentials-fetcher.service" << EOF
ExecStartPre=/bin/chgrp ec2-user /var/credentials-fetcher ${CF_KRB_DIR} ${CF_UNIX_DOMAIN_SOCKET_DIR} ${CF_LOGGING_DIR}
ExecStartPost=/bin/chgrp ec2-user /var/credentials-fetcher/socket/credentials_fetcher.sock
EOF
    elif [[ "${OS_ID}" == "ubuntu" ]]; then
        cat >> "${BUILD_DIR}/credentials-fetcher.service" << EOF
ExecStartPre=/bin/chgrp ubuntu /var/credentials-fetcher ${CF_KRB_DIR} ${CF_UNIX_DOMAIN_SOCKET_DIR} ${CF_LOGGING_DIR}
ExecStartPost=/bin/chgrp ubuntu /var/credentials-fetcher/socket/credentials_fetcher.sock
EOF
    fi
    
    cat >> "${BUILD_DIR}/credentials-fetcher.service" << EOF
ExecStartPre=/bin/chmod 750 /var/credentials-fetcher ${CF_KRB_DIR} ${CF_UNIX_DOMAIN_SOCKET_DIR} ${CF_LOGGING_DIR}
ExecStart=/usr/sbin/credentials-fetcherd
ExecStartPost=/bin/chmod 600 /var/credentials-fetcher/socket/credentials_fetcher.sock
Environment="CREDENTIALS_FETCHERD_STARTED_BY_SYSTEMD=1"
Type=notify
NotifyAccess=main
WatchdogSec=120s
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    log "Systemd service file created: ${BUILD_DIR}/credentials-fetcher.service"
}

# Install to system 
cf_install() {
    build
    cf_create_service
    
    log "Installing to system (requires sudo)..."
    
    sudo install -m 755 "${BIN_DIR}/credentials-fetcherd" /usr/sbin/
    sudo install -m 644 "${BUILD_DIR}/credentials-fetcher.service" /usr/lib/systemd/system/
    
    if [[ -f "configuration/conf/credentials-fetcher.conf" ]]; then
        sudo install -m 644 configuration/conf/credentials-fetcher.conf /etc/
    fi
    
    sudo systemctl daemon-reload
    log "Installation completed"
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
    security_check
    lint_check
    build
}

# Release-strict target 
release_strict() {
    security_check
    lint_check
    build
}

# All target - complete pipeline
all() {
    security_check
    lint_check
    test
    build
}

# Parse arguments
TARGET="${1:-build-only}"

case "${TARGET}" in
    -h|--help|help)
        usage
        exit 0
        ;;
    all)
        log "Running all target (security-check + lint-check + test + build)"
        all
        ;;
    build-only)
        log "Running build-only target (security-check + lint-check + build)"
        build_only
        ;;
    release-strict)
        log "Running release-strict target (security-check + lint-check + build)"
        release_strict
        ;;
    build)
        build
        ;;
    security-check)
        security_check
        ;;
    lint-check)
        lint_check
        ;;
    test)
        test
        ;;
    build-clean)
        build_clean
        ;;
    cf-create-service)
        cf_create_service
        ;;
    cf-install)
        cf_install
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