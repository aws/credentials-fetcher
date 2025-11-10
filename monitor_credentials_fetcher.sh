#!/bin/bash

# Real-time monitoring script for credentials-fetcher debugging
# This script provides continuous monitoring of the debug messages

echo "=== Real-time Credentials Fetcher Debug Monitor ==="
echo "Press Ctrl+C to exit"
echo ""

# Colors for different log levels
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Function to colorize output
colorize_log() {
    while IFS= read -r line; do
        case "$line" in
            *ERROR*)
                echo -e "${RED}$line${NC}"
                ;;
            *DEBUG*)
                echo -e "${BLUE}$line${NC}"
                ;;
            *INFO*)
                echo -e "${GREEN}$line${NC}"
                ;;
            *WARNING*)
                echo -e "${YELLOW}$line${NC}"
                ;;
            *RENEWAL*)
                echo -e "${PURPLE}$line${NC}"
                ;;
            *ldapsearch*)
                echo -e "${YELLOW}$line${NC}"
                ;;
            *KRB5CCNAME*)
                echo -e "${PURPLE}$line${NC}"
                ;;
            *)
                echo "$line"
                ;;
        esac
    done
}

# Monitor journal logs in real-time with filtering
journalctl -u credentials-fetcher -f --since "now" | \
    grep -E "(DEBUG|ERROR|INFO|WARNING|ldapsearch|KRB5CCNAME|RENEWAL|kinit|klist)" | \
    colorize_log
