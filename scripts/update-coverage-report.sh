#!/bin/bash

# Script to update the coverage report by removing proto files and other generated code
# This script is meant to be run after the Brazil build process completes

set -e

# Define paths
COVERAGE_FILE="build/brazil-documentation/coverage/coverage.out"
COVERAGE_HTML="build/brazil-documentation/coverage/coverage.html"
COVERAGE_DIR=$(dirname "$COVERAGE_FILE")

# Check if coverage file exists
if [ ! -f "$COVERAGE_FILE" ]; then
    echo "Coverage file not found: $COVERAGE_FILE"
    exit 1
fi

echo "Updating coverage report to exclude proto files and other generated code"

# Create a temporary file with filtered content
TEMP_FILE="${COVERAGE_FILE}.tmp"
grep -v "/proto/" "$COVERAGE_FILE" | grep -v "/cmd/credentials-fetcher/" | grep -v "/tests/test_client/" > "$TEMP_FILE"

# Replace the original file with the filtered content
mv "$TEMP_FILE" "$COVERAGE_FILE"

# Ensure the coverage directory exists
mkdir -p "$COVERAGE_DIR"

# Generate HTML report
echo "Generating HTML coverage report"
go tool cover -html="$COVERAGE_FILE" -o "$COVERAGE_HTML"

echo "Coverage report updated successfully"
echo "HTML report generated at: $COVERAGE_HTML"
echo "Excluded patterns:"
echo "  - /proto/"
echo "  - /cmd/credentials-fetcher/"
echo "  - /tests/test_client/"

# Print a summary of the coverage
echo ""
echo "Coverage Summary:"
go tool cover -func="$COVERAGE_FILE" | grep total:
