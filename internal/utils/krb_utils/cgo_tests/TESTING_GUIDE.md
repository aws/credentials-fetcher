# Testing Guide for Kerberos Ticket Renewal

This guide explains how to test the Kerberos ticket renewal functionality in the CredentialsFetcherV2 project.

## Overview

The `cgo_tests` directory contains integration tests that verify the Go-based Kerberos ticket renewal works correctly. The tests create a renewable ticket, then renew it using the `RenewTicket` flag, and verify the renewal succeeded using `klist`.

## Quick Start

```bash
# 1. Set your Kerberos credentials
export KRB5_TEST_USERNAME='your-username'
export KRB5_TEST_PASSWORD='your-password'
export KRB5_TEST_DOMAIN='EXAMPLE.COM'

# 2. Run the test
cd internal/utils/krb_utils/cgo_tests
./test_renewal.sh
```

## Test Structure

### Files

```
cgo_tests/
├── README.md              # Detailed documentation
├── TESTING_GUIDE.md       # This file
├── test_renewal.sh        # Main test script (bash)
├── test_renewal.go        # Go program for create/renew operations
├── test_renewal_manual.go # Manual testing helpers (from cgo/)
├── test_with_klist.go     # Klist integration tests (from cgo/)
└── .gitignore             # Excludes compiled binaries and artifacts
```

### Test Flow

```
┌─────────────────────────────────────────────────────┐
│ 1. Create Renewable Ticket (with password)         │
│    • Principal + Password → Initial Ticket          │
│    • RenewableLife = 24 hours                       │
│    • Verify with klist                              │
└──────────────────────┬──────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────┐
│ 2. Wait 5 Seconds                                   │
│    • Ensures timestamps will differ                 │
└──────────────────────┬──────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────┐
│ 3. Renew Ticket (NO password needed!)              │
│    • Uses RenewTicket: true flag                    │
│    • Equivalent to: kinit -R                        │
│    • Verify with klist                              │
└──────────────────────┬──────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────┐
│ 4. Verify Renewal Success                          │
│    • Ticket still valid (klist -s)                  │
│    • Timestamps updated                             │
│    • Compare initial vs renewed output              │
└─────────────────────────────────────────────────────┘
```

## Running Tests

### Automated Test (Recommended)

The shell script handles everything automatically:

```bash
./test_renewal.sh
```

**What it tests:**
- ✅ Ticket creation with renewable lifetime
- ✅ Ticket renewal without password
- ✅ Ticket validity after renewal
- ✅ Timestamp updates
- ✅ Cache file persistence
- ✅ Ticket flags (Forwardable, Renewable, Initial)

### Manual Testing

Build and run the test program directly:

```bash
# Build
go build -o test_renewal_program test_renewal.go

# Create renewable ticket
./test_renewal_program create \
    user@REALM.COM \
    'password123' \
    /tmp/test_krb5cc \
    86400

# Check ticket
klist -c /tmp/test_krb5cc

# Wait a few seconds (optional)
sleep 5

# Renew ticket
./test_renewal_program renew /tmp/test_krb5cc

# Verify renewal
klist -c /tmp/test_krb5cc
klist -s -c /tmp/test_krb5cc && echo "✓ Valid" || echo "✗ Invalid"
```

## Expected Results

### Successful Test Output

```
==> === Kerberos Ticket Renewal Test ===

✓ All required environment variables are set
==> Principal: webapp01@CONTOSO.COM

==> STEP 1: Creating initial renewable ticket...
✓ Successfully acquired Kerberos ticket for webapp01@CONTOSO.COM
✓ Initial ticket created

==> STEP 2: Checking initial ticket with klist...
Valid starting     Expires            Service principal
12/09/25 10:00:00  12/09/25 20:00:00  krbtgt/CONTOSO.COM@CONTOSO.COM
        renew until 12/10/25 10:00:00

==> STEP 4: Renewing ticket (kinit -R equivalent)...
✓ Successfully renewed Kerberos ticket
✓ Ticket renewed

==> STEP 5: Checking renewed ticket with klist...
Valid starting     Expires            Service principal
12/09/25 10:00:05  12/09/25 20:00:05  krbtgt/CONTOSO.COM@CONTOSO.COM
        renew until 12/10/25 10:00:05

==> STEP 6: Verifying renewal...
✓ Ticket cache file exists
✓ Ticket cache is readable
✓ Ticket is valid (klist -s passed)
✓ Expiry times differ - renewal updated the ticket

✓ === All tests passed! ===
```

### Key Indicators of Success

1. **Ticket created** - Initial ticket generation succeeds
2. **Renewal succeeds** - No errors during renewal
3. **klist -s passes** - Ticket is valid after renewal
4. **Timestamps updated** - Expiry times changed (usually)
5. **"renew until" date** - Shows ticket is renewable

## Troubleshooting

### Common Issues

#### 1. "KRB5_TEST_* is not set"

**Problem:** Environment variables missing

**Solution:**
```bash
export KRB5_TEST_USERNAME='your-username'
export KRB5_TEST_PASSWORD='your-password'
export KRB5_TEST_DOMAIN='EXAMPLE.COM'
```

#### 2. "Failed to renew ticket: KRB5KRB_AP_ERR_TKT_EXPIRED"

**Problem:** Ticket expired before renewal

**Solution:** Reduce the wait time in the script or create a ticket with longer lifetime

#### 3. "Ticket is not renewable"

**Problem:** Initial ticket created without renewable lifetime

**Solution:** Check that `RenewableLife` is set when creating the ticket:
```go
config.RenewableLife = 86400  // 24 hours
```

#### 4. Timestamps Don't Change

**Problem:** KDC doesn't update timestamps on renewal

**Status:** This is normal for some KDC configurations

**Verification:** Check that `klist -s` still passes - that's the important test

#### 5. "Permission denied" on test_renewal.sh

**Problem:** Script not executable

**Solution:**
```bash
chmod +x test_renewal.sh
```

## Integration Testing

### Test with Actual CredentialsFetcher

To test renewal in the context of the full application:

```go
// In internal/auth/kerberos/krb_client.go
func (c *Client) RenewKerberosTicket(ctx context.Context, krbFilePath string) error {
    log.Info("Renewing Kerberos ticket using Go implementation",
        "krb_file_path", krbFilePath)

    config := &krb_utils.KinitConfig{
        CCachePath:  krbFilePath,
        RenewTicket: true,
        Verify:      true,
    }

    if err := krb_utils.GenerateKerberosTicket(config); err != nil {
        return fmt.Errorf("failed to renew ticket: %w", err)
    }

    log.Info("Successfully renewed Kerberos ticket",
        "krb_file_path", krbFilePath)
    return nil
}
```

### Unit Testing

Mock the renewal functionality:

```go
mockClient := new(krb5ClientMock)
mockClient.On("GenerateTicket", mock.MatchedBy(func(cfg *KinitConfig) bool {
    return cfg.RenewTicket && cfg.CCachePath == "/expected/path"
})).Return(nil)

config := &KinitConfig{
    CCachePath:  "/expected/path",
    RenewTicket: true,
}

err := mockClient.GenerateTicket(config)
assert.NoError(t, err)
mockClient.AssertExpectations(t)
```

## CI/CD Integration

### Skip in CI (Recommended)

Since these tests require valid Kerberos credentials, skip them in CI:

```yaml
# In your CI config
test:
  script:
    - go test ./... -v
    # Skip cgo_tests in CI (requires credentials)
    - go test ./... -v --tags=!integration
```

### Or Mock the KDC

For CI testing, consider setting up a mock KDC:
- MIT Kerberos test server
- Docker container with KDC
- Mock KDC service

## Security Best Practices

1. **Never commit credentials**
   - Use environment variables
   - Add `.env` files to `.gitignore`
   - Use secret management in production

2. **Clean up test artifacts**
   - The script auto-cleans on exit
   - Check `/tmp/krb_renewal_test_*` directories

3. **Use restrictive permissions**
   - Ticket caches: `0600` (owner read/write only)
   - Scripts: `0700` (owner execute only)

4. **Rotate test credentials**
   - Don't use production credentials for testing
   - Use dedicated test accounts
   - Rotate passwords regularly

## Performance Considerations

### Timing Expectations

| Operation | Expected Duration |
|-----------|------------------|
| Create ticket | < 1 second |
| Renew ticket | < 500ms |
| klist verification | < 100ms |
| Full test script | ~10 seconds |

### Network Considerations

- Tests require network access to KDC
- Timeouts: Default 30 seconds
- Retry logic: Not implemented (fail fast)

## Future Improvements

Potential enhancements for the test suite:

1. **Multiple Renewal Cycles**
   - Test renewing multiple times
   - Verify renewable period countdown

2. **Expiry Testing**
   - Test renewal of near-expired tickets
   - Verify failure for fully expired tickets

3. **Concurrent Renewal**
   - Test multiple renewal attempts
   - Verify thread safety

4. **Performance Benchmarks**
   - Measure renewal latency
   - Compare with shell-based `kinit -R`

5. **Error Scenarios**
   - Network failures
   - KDC unavailable
   - Corrupted cache files

## Resources

- [MIT Kerberos Documentation](https://web.mit.edu/kerberos/)
- [kinit man page](https://web.mit.edu/kerberos/krb5-latest/doc/user/user_commands/kinit.html)
- [Kerberos Ticket Renewal RFC](https://www.rfc-editor.org/rfc/rfc4120.html#section-3.3)
- [Go CGO Documentation](https://pkg.go.dev/cmd/cgo)

## Support

For issues or questions:
1. Check the [README.md](./README.md) for detailed information
2. Review test output for specific error messages
3. Check Kerberos logs: `/var/log/krb5*` or `journalctl -u krb5*`
4. Verify KDC connectivity: `kinit username@REALM.COM`
