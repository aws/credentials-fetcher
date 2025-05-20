package grpc

import (
	"context"
	"net"
	"os"
	"path/filepath"
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

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

// setupGrpcServer sets up a test gRPC server using bufconn
func setupGrpcServer(t *testing.T) (*grpc.ClientConn, *CredentialsFetcherServer, func()) {
	lis = bufconn.Listen(bufSize)
	server := NewCredentialsFetcherServer(constants.DefaultKrbFilesDir, constants.DefaultAWSSecretName).(*CredentialsFetcherServer)
	s := grpc.NewServer()
	pb.RegisterCredentialsFetcherServiceServer(s, server)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("Server exited with error: %v", err)
		}
	}()

	// Connect to the server
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	return conn, server, func() {
		conn.Close()
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
		CredspecContents: []string{"test-credspec"},
	}
	resp, err := client.AddKerberosLease(context.Background(), req)

	// Verify response
	assert.NoError(t, err)
	assert.Equal(t, "", resp.LeaseId)
	assert.Empty(t, resp.CreatedKerberosFilePaths)
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

func TestCredentialsFetcherServer_DeleteKerberosLease(t *testing.T) {
	// Setup server
	conn, _, cleanup := setupGrpcServer(t)
	defer cleanup()

	// Create client
	client := pb.NewCredentialsFetcherServiceClient(conn)

	// Test DeleteKerberosLease
	req := &pb.DeleteKerberosLeaseRequest{
		LeaseId: "test-lease-id",
	}
	resp, err := client.DeleteKerberosLease(context.Background(), req)

	// Verify response
	assert.NoError(t, err)
	assert.Equal(t, "", resp.LeaseId)
	assert.Empty(t, resp.DeletedKerberosFilePaths)
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

	// Verify response
	assert.NoError(t, err)
	assert.Equal(t, "", resp.LeaseId)
	assert.Empty(t, resp.KrbTicketResponseMap)
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
	assert.Equal(t, "OK", resp.Status)
}

func TestCredentialsFetcherServer_RunServer(t *testing.T) {
	// Create a temporary directory for the socket
	tempDir := t.TempDir()

	// Create the socket directory
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a server
	server := NewCredentialsFetcherServer(constants.DefaultKrbFilesDir, constants.DefaultAWSSecretName)

	// Start the server in a goroutine
	go func() {
		err := server.RunServer(tempDir)
		assert.NoError(t, err)
	}()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Check that the socket file was created
	socketPath := filepath.Join(tempDir, "credentials_fetcher.sock")
	_, err = os.Stat(socketPath)
	assert.NoError(t, err)

	// Connect to the server
	conn, err := grpc.Dial(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	assert.NoError(t, err)
	defer conn.Close()

	// Create a client
	client := pb.NewCredentialsFetcherServiceClient(conn)

	// Test that the server is responding
	resp, err := client.HealthCheck(context.Background(), &pb.HealthCheckRequest{Service: "test"})
	assert.NoError(t, err)
	assert.Equal(t, "OK", resp.Status)

	// Shutdown the server
	server.Shutdown()

	// Give the server time to shut down
	time.Sleep(100 * time.Millisecond)
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
