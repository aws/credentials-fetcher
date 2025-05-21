# Makefile for credentials-fetcher Go daemon

# Version
VERSION := 1.3.8

# Run the strict release to allow vetting and race detection.
BGO_RELEASE_TARGET=release-strict

# Define the default target for brazil-build (without install)
BGO_DEFAULT_TARGET=build-only

# Coverage configuration for Brazil
BGO_TEST_COVERAGE_EXCLUDE_PKGS=golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto,golang.a2z.com/CredentialsFetcherV2/cmd/credentials-fetcher,golang.a2z.com/CredentialsFetcherV2/tests/test_client

# Directories
BIN_DIR := bin
BUILD_DIR := build
SCRIPTS_DIR := scripts

# Go build flags
GO_FLAGS := -trimpath -buildvcs=0 -ldflags="-s -w -X main.Version=$(VERSION)"

# Conditional flags
ifeq ($(ENABLE_DEBUGGING),1)
    GO_FLAGS += -gcflags="all=-N -l"
else
    GO_FLAGS += -ldflags="-s -w -X main.Version=$(VERSION)"
endif

ifeq ($(CODE_COVERAGE),1)
    GO_FLAGS += -cover
endif

# Detect OS
OS := $(shell cat /etc/os-release | grep ^ID= | cut -d'=' -f2 | tr -d '"')

# Configuration
CF_KRB_DIR ?= /var/credentials-fetcher/krbdir
CF_UNIX_DOMAIN_SOCKET_DIR ?= /var/credentials-fetcher/socket
CF_LOGGING_DIR ?= /var/credentials-fetcher/logging
CF_TEST_DOMAIN_NAME ?= contoso.com
CF_TEST_GMSA_ACCOUNT ?= webapp01

# Defines a bunch of standard build targets.
# For more info see: https://code.amazon.com/packages/BrazilMakeGo/blobs/mainline/--/configuration/bin/bgo.makefile
include ${BGO_MAKEFILE}

# Main targets
release-strict:: security-check lint-check build test

# Define a build-only target that doesn't include install
.PHONY: build-only
build-only:: security-check lint-check build test

.PHONY: security-check
security-check::
	mkdir -p build/private/gosec
	gosec -exclude-generated -exclude="**/proto/*.pb.go" -fmt=json -out=build/private/gosec/results.json ./... || (cat build/private/gosec/results.json ; echo; echo "GoSec returned with error. Fix the errors above or add the comment '/* #nosec */' to ignore the affected line."; exit 1)

.PHONY: lint-check
lint-check::
	@if which golangci-lint > /dev/null 2>&1; then \
		echo "Running golangci-lint..."; \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found. Skipping lint check."; \
	fi

.PHONY: build
build:: $(BIN_DIR)/credentials-fetcherd

$(BIN_DIR)/credentials-fetcherd:
	mkdir -p $(BIN_DIR)
	go build $(GO_FLAGS) -o $@ ./cmd/credentials-fetcher/main.go

.PHONY: test
test::
	go test ./...
	@if [ -f build/brazil-documentation/coverage/coverage.out ]; then \
		./scripts/fix-coverage.sh; \
	fi

# Define a custom install target that won't be run by default
.PHONY: cf-install
cf-install:: build cf-create-service
	sudo install -m 755 $(BIN_DIR)/credentials-fetcherd /usr/sbin/
	sudo install -m 644 $(BUILD_DIR)/credentials-fetcher.service /usr/lib/systemd/system/
	sudo systemctl daemon-reload

# Create systemd service file
.PHONY: cf-create-service
cf-create-service::
	mkdir -p $(BUILD_DIR)
	@echo "[Unit]" > $(BUILD_DIR)/credentials-fetcher.service
	@echo "Description=credentials-fetcher systemd service unit file." >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "[Service]" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "StandardError=journal" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "StandardOutput=journal" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "StandardInput=null" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "ExecStartPre=/bin/mkdir -p $(CF_KRB_DIR) $(CF_UNIX_DOMAIN_SOCKET_DIR) $(CF_LOGGING_DIR)" >> $(BUILD_DIR)/credentials-fetcher.service
ifeq ($(OS),amzn)
	@echo "ExecStartPre=/bin/chgrp ec2-user /var/credentials-fetcher $(CF_KRB_DIR) $(CF_UNIX_DOMAIN_SOCKET_DIR) $(CF_LOGGING_DIR)" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "ExecStartPost=/bin/chgrp ec2-user /var/credentials-fetcher/socket/credentials_fetcher.sock" >> $(BUILD_DIR)/credentials-fetcher.service
else ifeq ($(OS),ubuntu)
	@echo "ExecStartPre=/bin/chgrp ubuntu /var/credentials-fetcher $(CF_KRB_DIR) $(CF_UNIX_DOMAIN_SOCKET_DIR) $(CF_LOGGING_DIR)" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "ExecStartPost=/bin/chgrp ubuntu /var/credentials-fetcher/socket/credentials_fetcher.sock" >> $(BUILD_DIR)/credentials-fetcher.service
endif
	@echo "ExecStartPre=/bin/chmod 755 /var/credentials-fetcher $(CF_KRB_DIR) $(CF_UNIX_DOMAIN_SOCKET_DIR) $(CF_LOGGING_DIR)" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "ExecStart=/usr/sbin/credentials-fetcherd" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "ExecStartPost=/bin/chmod 660 /var/credentials-fetcher/socket/credentials_fetcher.sock" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "Environment=\"CREDENTIALS_FETCHERD_STARTED_BY_SYSTEMD=1\"" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "Type=notify" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "NotifyAccess=main" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "WatchdogSec=120s" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "Restart=on-failure" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "[Install]" >> $(BUILD_DIR)/credentials-fetcher.service
	@echo "WantedBy=multi-user.target" >> $(BUILD_DIR)/credentials-fetcher.service

# Additional targets (you might need to implement these in Go)
.PHONY: check_help
check_help::
	$(BIN_DIR)/credentials-fetcherd --help

# Tools installation (if needed)
.PHONY: install-tools
install-tools::
	@echo "Installing required tools..."
	@which gosec > /dev/null 2>&1 || go install github.com/securego/gosec/v2/cmd/gosec@latest
	@which golangci-lint > /dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
