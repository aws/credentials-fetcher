#!/bin/bash

# Credentials Fetcher Debug Helper Script
# This script helps monitor and debug gMSA ticket renewal issues

LOG_FILE="/var/log/credentials-fetcher-debug.log"
JOURNAL_LINES=500

echo "=== Credentials Fetcher Debug Information ===" | tee -a "$LOG_FILE"
echo "Timestamp: $(date)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Function to log with timestamp
log_with_timestamp() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Check service status
log_with_timestamp "=== SERVICE STATUS ==="
systemctl status credentials-fetcher --no-pager | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Check current environment variables
log_with_timestamp "=== ENVIRONMENT VARIABLES ==="
log_with_timestamp "KRB5CCNAME: ${KRB5CCNAME:-NOT_SET}"
log_with_timestamp "CF_KRB_DIR: ${CF_KRB_DIR:-NOT_SET}"
log_with_timestamp "CF_UNIX_DOMAIN_SOCKET_DIR: ${CF_UNIX_DOMAIN_SOCKET_DIR:-NOT_SET}"
echo "" | tee -a "$LOG_FILE"

# Check current tickets in all caches
log_with_timestamp "=== CURRENT KERBEROS TICKETS ==="
log_with_timestamp "Default cache (klist):"
klist 2>&1 | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

log_with_timestamp "All caches (klist -A):"
klist -A 2>&1 | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

log_with_timestamp "List all credential caches (klist -l):"
klist -l 2>&1 | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Check credentials-fetcher directory structure
log_with_timestamp "=== CREDENTIALS-FETCHER DIRECTORY STRUCTURE ==="
if [ -d "/var/credentials-fetcher/krbdir" ]; then
    log_with_timestamp "Contents of /var/credentials-fetcher/krbdir:"
    find /var/credentials-fetcher/krbdir -type f -name "krb5cc" -exec ls -la {} \; 2>&1 | tee -a "$LOG_FILE"
    find /var/credentials-fetcher/krbdir -type f -name "*_metadata" -exec ls -la {} \; 2>&1 | tee -a "$LOG_FILE"
else
    log_with_timestamp "/var/credentials-fetcher/krbdir does not exist"
fi
echo "" | tee -a "$LOG_FILE"

# Check for specific tickets in credentials-fetcher caches
log_with_timestamp "=== CREDENTIALS-FETCHER SPECIFIC TICKETS ==="
if [ -d "/var/credentials-fetcher/krbdir" ]; then
    find /var/credentials-fetcher/krbdir -name "krb5cc" | while read cache_file; do
        log_with_timestamp "Checking cache: $cache_file"
        KRB5CCNAME="$cache_file" klist 2>&1 | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
    done
fi

# Get recent journal logs with our debug messages
log_with_timestamp "=== RECENT JOURNAL LOGS (DEBUG) ==="
journalctl -u credentials-fetcher --since "1 hour ago" -n "$JOURNAL_LINES" | grep -E "(DEBUG|ERROR|INFO)" | tail -50 | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Check for LDAP errors specifically
log_with_timestamp "=== RECENT LDAP ERRORS ==="
journalctl -u credentials-fetcher --since "1 hour ago" | grep -i "ldap" | tail -20 | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Check for KRB5CCNAME related messages
log_with_timestamp "=== KRB5CCNAME RELATED MESSAGES ==="
journalctl -u credentials-fetcher --since "1 hour ago" | grep -i "krb5ccname" | tail -20 | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Test LDAP connectivity
log_with_timestamp "=== LDAP CONNECTIVITY TEST ==="
if command -v ldapsearch >/dev/null 2>&1; then
    # Try a simple LDAP search to check connectivity
    timeout 10 ldapsearch -LLL -Y GSSAPI -H ldap://$(hostname -d) -b "" -s base "(objectclass=*)" 2>&1 | head -10 | tee -a "$LOG_FILE"
else
    log_with_timestamp "ldapsearch command not available"
fi
echo "" | tee -a "$LOG_FILE"

# Check network connectivity to domain controllers
log_with_timestamp "=== NETWORK CONNECTIVITY ==="
if [ -n "$(hostname -d)" ]; then
    DOMAIN=$(hostname -d)
    log_with_timestamp "Testing connectivity to domain: $DOMAIN"
    nslookup "$DOMAIN" 2>&1 | tee -a "$LOG_FILE"
    
    # Try to reach LDAP port
    timeout 5 nc -zv "$DOMAIN" 389 2>&1 | tee -a "$LOG_FILE"
    timeout 5 nc -zv "$DOMAIN" 636 2>&1 | tee -a "$LOG_FILE"
fi
echo "" | tee -a "$LOG_FILE"

log_with_timestamp "=== DEBUG COLLECTION COMPLETE ==="
log_with_timestamp "Full log saved to: $LOG_FILE"

# Provide recommendations
echo ""
echo "=== DEBUGGING RECOMMENDATIONS ==="
echo "1. Monitor the log file: tail -f $LOG_FILE"
echo "2. Watch journal logs: journalctl -u credentials-fetcher -f"
echo "3. Look for DEBUG messages in the output above"
echo "4. Pay attention to KRB5CCNAME values and LDAP error patterns"
echo "5. Check if tickets are being created in the right cache locations"
echo ""
echo "Key things to look for:"
echo "- KRB5CCNAME environment variable settings"
echo "- Whether ldapsearch is using the right credential cache"
echo "- Timing of ticket renewal attempts vs. ticket expiration"
echo "- Network connectivity issues to domain controllers"
