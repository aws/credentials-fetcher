# Open Source Makefile for credentials-fetcher
# Simple, clean build system focused on core functionality

# Load configuration from build.conf if it exists
-include config/build.conf

# Default values (can be overridden by environment variables or build.conf)
VERSION ?= 2.0.0
BIN_DIR ?= bin
BUILD_DIR ?= build
ENABLE_DEBUGGING ?= 0
CODE_COVERAGE ?= 0

# Build flags for reproducible, optimized binaries
# -trimpath: removes file system paths from binary (for reproducible builds)
# -buildvcs=0: disables VCS info embedding (for reproducible builds)
BUILD_FLAGS ?= -trimpath -buildvcs=0

# Go build flags - combines BUILD_FLAGS with linker flags
# ldflags: -s (strip symbol table) + -w (strip debug info)
LDFLAGS = -s -w
GO_FLAGS = $(BUILD_FLAGS) -ldflags="$(LDFLAGS)"

# Add debug flags if enabled
ifeq ($(ENABLE_DEBUGGING),1)
    GO_FLAGS += -gcflags="all=-N -l"
endif

# Add coverage flags if enabled
ifeq ($(CODE_COVERAGE),1)
    GO_FLAGS += -cover
    TEST_FLAGS += -cover
endif

# Project paths
PROJECT_ROOT = ..
BINARY_NAME = credentials-fetcherd
MAIN_PATH = ./cmd/credentials-fetcher/main.go

# Default target
.DEFAULT_GOAL := build

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME) binary..."
	@mkdir -p $(BIN_DIR)
	@cd $(PROJECT_ROOT) && go build $(GO_FLAGS) -o opensource/$(BIN_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Binary built successfully: $(BIN_DIR)/$(BINARY_NAME)"

# Run tests
.PHONY: test
test:
	@echo "Running Go tests..."
	@cd $(PROJECT_ROOT) && go test -v $(TEST_FLAGS) ./...
	@echo "All tests passed"

# Build and test (complete pipeline)
.PHONY: all
all: test build

# Clean build artifacts
.PHONY: build-clean
build-clean:
	@echo "Cleaning build directory..."
	@rm -rf $(BUILD_DIR)/gopath
	@mkdir -p $(BUILD_DIR)
	@echo "Build directory cleaned"

# Clean all artifacts
.PHONY: clean
clean:
	@echo "Cleaning all build artifacts..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "All artifacts cleaned"

# Show binary help
.PHONY: check_help
check_help:
	@if [ ! -x "$(BIN_DIR)/$(BINARY_NAME)" ]; then \
		echo "Binary not found. Run 'make build' first."; \
		exit 1; \
	fi
	@$(BIN_DIR)/$(BINARY_NAME) --help

# Alias for build (for compatibility)
.PHONY: build-only
build-only: build

# Show help
.PHONY: help
help:
	@echo "Open Source Build System for credentials-fetcher"
	@echo ""
	@echo "TARGETS:"
	@echo "  build        Build binary only (default)"
	@echo "  test         Run tests"
	@echo "  all          Run complete pipeline: test and build"
	@echo "  build-clean  Clean build artifacts"
	@echo "  clean        Clean all artifacts"
	@echo "  check_help   Show binary help"
	@echo "  help         Show this help"
	@echo ""
	@echo "ENVIRONMENT VARIABLES:"
	@echo "  VERSION             Version to embed (default: $(VERSION))"
	@echo "  ENABLE_DEBUGGING    Enable debug symbols (0/1, default: $(ENABLE_DEBUGGING))"
	@echo "  CODE_COVERAGE       Enable code coverage (0/1, default: $(CODE_COVERAGE))"
	@echo "  BIN_DIR             Binary output directory (default: $(BIN_DIR))"
	@echo "  BUILD_DIR           Build artifacts directory (default: $(BUILD_DIR))"