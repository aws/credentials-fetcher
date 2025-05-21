#!/bin/bash

# Script to generate HTML coverage report from the coverage.out file
# This script can be run independently after the tests have been run

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

# Ensure the coverage directory exists
mkdir -p "$COVERAGE_DIR"

# Generate HTML report
echo "Generating HTML coverage report"
go tool cover -html="$COVERAGE_FILE" -o "$COVERAGE_HTML"

echo "HTML coverage report generated at: $COVERAGE_HTML"

# Open the HTML report if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$COVERAGE_HTML"
fi
