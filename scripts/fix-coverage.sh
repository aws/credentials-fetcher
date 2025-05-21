#!/bin/bash

# Script to post-process coverage output to exclude proto files and other generated code
# Usage: ./scripts/fix-coverage.sh [coverage_file]

set -e

COVERAGE_FILE=${1:-"build/brazil-documentation/coverage/coverage.out"}
TEMP_FILE="${COVERAGE_FILE}.tmp"

if [ ! -f "$COVERAGE_FILE" ]; then
    echo "Coverage file not found: $COVERAGE_FILE"
    exit 1
fi

echo "Processing coverage file: $COVERAGE_FILE"

# Create a temporary file with filtered content
grep -v "/proto/" "$COVERAGE_FILE" | grep -v "/cmd/credentials-fetcher/" | grep -v "/tests/test_client/" > "$TEMP_FILE"

# Replace the original file with the filtered content
mv "$TEMP_FILE" "$COVERAGE_FILE"

echo "Coverage file updated to exclude proto files and other generated code"
echo "Excluded patterns:"
echo "  - /proto/"
echo "  - /cmd/credentials-fetcher/"
echo "  - /tests/test_client/"
