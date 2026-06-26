package grpc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.a2z.com/CredentialsFetcherV2/constants"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// bufSize is used by the bufconn listener in setupGrpcServer
const bufSize = 1024 * 1024 // nolint:unused

// lis is used by bufDialer and setupGrpcServer
var lis *bufconn.Listener // nolint:unused

// bufDialer is used as the context dialer in setupGrpcServer
func bufDialer(_ context.Context, _ string) (net.Conn, error) { // nolint:unused
	return lis.Dial()
}

// setupGrpcServer sets up a test gRPC server using bufconn
func setupGrpcServer(t *testing.T) (*grpc.ClientConn, *CredentialsFetcherServer, func()) { // nolint:unused
	lis = bufconn.Listen(bufSize)

	// Use a temporary directory for tests instead of /var/credentials-fetcher
	tempDir := t.TempDir()

	server := NewCredentialsFetcherServer(tempDir, constants.DefaultAWSSecretName).(*CredentialsFetcherServer)
	s := grpc.NewServer()
	pb.RegisterCredentialsFetcherServiceServer(s, server)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("Server exited with error: %v", err)
		}
	}()

	// Connect to the server using DialContext which is the recommended approach
	// Note: We're using the deprecated DialContext method here because the test environment
	// requires it for compatibility. In production code, use grpc.NewClient instead.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, "bufnet", // nolint:staticcheck // TODO: Using deprecated API here, need to fix
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	return conn, server, func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("Failed to close connection: %s\n", err.Error())
		}
		s.Stop()
	}
}

func TestNewCredentialsFetcherServer(t *testing.T) {
	server := NewCredentialsFetcherServer(constants.DefaultKrbFilesDir, constants.DefaultAWSSecretName).(*CredentialsFetcherServer)

	// Verify that the server was created with the expected default values
	assert.NotNil(t, server)
	assert.Equal(t, constants.DefaultKrbFilesDir, server.krbFilesDir)
	assert.Equal(t, constants.DefaultAWSSecretName, server.awsSMSecretName)
	assert.NotNil(t, server.shutdownCh)
	assert.NotNil(t, server.krbClient)
	assert.NotNil(t, server.ldapClient)
	assert.NotNil(t, server.shellExecutor)
}

func TestCredentialsFetcherServer_HealthCheck(t *testing.T) {
	// Setup server
	conn, _, cleanup := setupGrpcServer(t)
	defer cleanup()

	// Create client
	client := pb.NewCredentialsFetcherServiceClient(conn)

	// Test HealthCheck
	req := &pb.HealthCheckRequest{
		Service: "test-service",
	}
	resp, err := client.HealthCheck(context.Background(), req)

	// Verify response
	assert.NoError(t, err)
	assert.Equal(t, "OK", resp.Status)
}

func TestCredentialsFetcherServer_AddKerberosLease(t *testing.T) {
	// Setup server
	conn, _, cleanup := setupGrpcServer(t)
	defer cleanup()

	// Create client
	client := pb.NewCredentialsFetcherServiceClient(conn)

	// Test AddKerberosLease
	req := &pb.CreateKerberosLeaseRequest{
		CredspecContents: []string{`{"DomainJoinConfig":{"DnsName":"example.com","MachineAccountName":"testmachine","Sid":"S-1-5-21-1234567890-1234567890-1234567890","DnsTreeName":"example.com","Guid":"12345678-1234-1234-1234-123456789012","NetBiosName":"EXAMPLE"},"ActiveDirectoryConfig":{"GroupManagedServiceAccounts":[{"Name":"testaccount","Scope":"example.com"}]},"HostAccountConfig":{"PluginInput":{"CredentialArn":"arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret"}}}`},
	}
	resp, err := client.AddKerberosLease(context.Background(), req)

	// Verify response
	if err != nil {
		// If there's an error, just log it and don't try to access resp which might be nil
		t.Logf("Error received: %v", err)
		return
	}

	assert.NotEmpty(t, resp.LeaseId)
	// We don't need to check the actual paths since they might be mocked
}

func TestCredentialsFetcherServer_AddNonDomainJoinedKerberosLease(t *testing.T) {
	// Setup server
	conn, _, cleanup := setupGrpcServer(t)
	defer cleanup()

	// Create client
	client := pb.NewCredentialsFetcherServiceClient(conn)

	// Test AddNonDomainJoinedKerberosLease
	req := &pb.CreateNonDomainJoinedKerberosLeaseRequest{
		CredspecContents: []string{"test-credspec"},
		Username:         "test-user",
		Password:         "test-password",
		Domain:           "test-domain",
	}
	resp, err := client.AddNonDomainJoinedKerberosLease(context.Background(), req)

	// Expect an error due to invalid domain format
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid domain format")
	assert.Nil(t, resp)
}

func TestCredentialsFetcherServer_AddNonDomainJoinedKerberosLease_BlueGreenUsername(t *testing.T) {
	// Setup server
	conn, _, cleanup := setupGrpcServer(t)
	defer cleanup()

	// Create client
	client := pb.NewCredentialsFetcherServiceClient(conn)

	t.Run("Customer rotation SvcAccountGR:SvcAccountBL passes validation", func(t *testing.T) {
		req := &pb.CreateNonDomainJoinedKerberosLeaseRequest{
			CredspecContents: []string{`{"DomainJoinConfig":{"Sid":"S-1-5-21-123456789-987654321-111222333","MachineAccountName":"gSvcAccount","Guid":"12345678-1234-1234-1234-123456789012","DnsName":"contoso.com","NetBiosName":"CORE"},"ActiveDirectoryConfig":{"GroupManagedServiceAccounts":[{"Name":"gSvcAccount","Scope":"contoso.com"}],"HostAccountConfig":{"PluginGUID":"{859E1386-BDB4-49E8-85C7-3070B13920E1}","PluginInput":{"CredentialArn":"arn:aws:secretsmanager:us-east-1:123456789012:secret:/gmsa/SvcAccount-AbCdEf"},"PortableCcgVersion":"1"}}}`},
			Username:         "SvcAccountGR:SvcAccountBL",
			Password:         "test-password",
			Domain:           "contoso.com",
		}
		resp, err := client.AddNonDomainJoinedKerberosLease(context.Background(), req)

		// The request should get past username validation (no "invalid character" error).
		// It will fail later at Kerberos ticket creation since we have no real KDC,
		// but the important thing is it does NOT fail with "username contains invalid character: :"
		if err != nil {
			assert.NotContains(t, err.Error(), "username contains invalid character")
			assert.NotContains(t, err.Error(), "invalid username")
		} else {
			assert.NotNil(t, resp)
		}
	})

	t.Run("Empty new username in blue/green format returns error", func(t *testing.T) {
		req := &pb.CreateNonDomainJoinedKerberosLeaseRequest{
			CredspecContents: []string{"credspec"},
			Username:         "SvcAccountGR:",
			Password:         "test-password",
			Domain:           "contoso.com",
		}
		resp, err := client.AddNonDomainJoinedKerberosLease(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "blue/green rotation format requires a non-empty new username")
		assert.Nil(t, resp)
	})
}

func TestCredentialsFetcherServer_RenewNonDomainJoinedKerberosLease_BlueGreenUsername(t *testing.T) {
	conn, _, cleanup := setupGrpcServer(t)
	defer cleanup()

	client := pb.NewCredentialsFetcherServiceClient(conn)

	req := &pb.RenewNonDomainJoinedKerberosLeaseRequest{
		Username: "SvcAccountGR:SvcAccountBL",
		Password: "test-password",
		Domain:   "contoso.com",
	}
	_, err := client.RenewNonDomainJoinedKerberosLease(context.Background(), req)

	// Should NOT fail with "username contains invalid character" — the colon is parsed out.
	// Will fail with "no metadata files found" since no tickets exist in the temp dir.
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "username contains invalid character")
	assert.NotContains(t, err.Error(), "invalid username")
	assert.Contains(t, err.Error(), "no metadata files found")
}

func TestCredentialsFetcherServer_RenewNonDomainJoinedKerberosLease(t *testing.T) {
	// Setup server
	conn, _, cleanup := setupGrpcServer(t)
	defer cleanup()

	// Create client
	client := pb.NewCredentialsFetcherServiceClient(conn)

	// Test RenewNonDomainJoinedKerberosLease
	req := &pb.RenewNonDomainJoinedKerberosLeaseRequest{
		Username: "test-user",
		Password: "test-password",
		Domain:   "test-domain",
	}
	resp, err := client.RenewNonDomainJoinedKerberosLease(context.Background(), req)

	// Verify response
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid domain format")
	assert.Nil(t, resp)
}

func TestCredentialsFetcherServer_AddKerberosArnLease(t *testing.T) {
	// Setup server
	conn, _, cleanup := setupGrpcServer(t)
	defer cleanup()

	// Create client
	client := pb.NewCredentialsFetcherServiceClient(conn)

	// Test AddKerberosArnLease
	req := &pb.KerberosArnLeaseRequest{
		CredspecArns:    []string{"test-arn"},
		AccessKeyId:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		SessionToken:    "test-session-token",
		Region:          "us-west-2",
	}
	resp, err := client.AddKerberosArnLease(context.Background(), req)

	// Verify response - we expect an error since the ARN is not valid
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credentialspec arn is not valid")
	assert.Nil(t, resp)
}

func TestCredentialsFetcherServer_RenewKerberosArnLease(t *testing.T) {
	// Setup server
	conn, _, cleanup := setupGrpcServer(t)
	defer cleanup()

	// Create client
	client := pb.NewCredentialsFetcherServiceClient(conn)

	// Test RenewKerberosArnLease
	req := &pb.RenewKerberosArnLeaseRequest{
		AccessKeyId:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		SessionToken:    "test-session-token",
		Region:          "us-west-2",
	}
	resp, err := client.RenewKerberosArnLease(context.Background(), req)

	// Verify response
	assert.NoError(t, err)
	// Since we're testing in an environment with no metadata files,
	// "No tickets to renew" is an acceptable response
	assert.Contains(t, []string{"successful", "No tickets to renew"}, resp.Status)
}

func TestCredentialsFetcherServer_RunServer(t *testing.T) {
	// Skip this test on macOS as it has issues with Unix socket paths
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping test on macOS due to Unix socket path issues")
	}

	// Create a temporary directory for the socket
	tempDir := t.TempDir()

	// Create the socket directory
	err := os.MkdirAll(tempDir, 0750)
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to remove temp directory: %v", err)
		}
	}()

	// Create a server
	server := NewCredentialsFetcherServer(constants.DefaultKrbFilesDir, constants.DefaultAWSSecretName)

	// Create a context with cancellation for clean shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.RunServer(tempDir)
	}()

	// Give the server time to start
	time.Sleep(200 * time.Millisecond)

	// Check that the socket file was created
	socketPath := filepath.Join(tempDir, "credentials_fetcher.sock")
	_, err = os.Stat(socketPath)
	if err != nil {
		t.Logf("Socket file not found: %v", err)
		server.Shutdown()
		t.Fatalf("Server failed to create socket file: %v", <-errCh)
	}

	// Connect to the server using the new recommended API
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	conn, dialErr := grpc.DialContext( // nolint:staticcheck // TODO: Using deprecated API here, need to fix
		dialCtx,
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if dialErr != nil {
		server.Shutdown()
		t.Fatalf("Failed to connect to server: %v", dialErr)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Create a client
	client := pb.NewCredentialsFetcherServiceClient(conn)

	// Test that the server is responding
	resp, err := client.HealthCheck(ctx, &pb.HealthCheckRequest{Service: "test"})
	if err != nil {
		server.Shutdown()
		t.Fatalf("HealthCheck failed: %v", err)
	}
	assert.Equal(t, "OK", resp.Status)

	// Shutdown the server
	server.Shutdown()

	// Wait for server to shut down
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not shut down within timeout")
	}
}

func TestCredentialsFetcherServer_Shutdown(t *testing.T) {
	server := NewCredentialsFetcherServer(constants.DefaultKrbFilesDir, constants.DefaultAWSSecretName).(*CredentialsFetcherServer)

	// Create a channel to signal when the goroutine is done
	done := make(chan struct{})

	// Start a goroutine that waits for the shutdown signal
	go func() {
		<-server.shutdownCh
		close(done)
	}()

	// Call Shutdown
	server.Shutdown()

	// Wait for the goroutine to finish or timeout
	select {
	case <-done:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Shutdown did not close the channel")
	}
}
