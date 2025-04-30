package grpc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.a2z.com/CredentialsFetcherV2/internal/auth/kerberos"
	"golang.a2z.com/CredentialsFetcherV2/internal/auth/ldap"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/shell"
	"google.golang.org/grpc"
)

// Create a package-level logger instance
var log = logger.New()

// CredentialsFetcherServer implements the CredentialsFetcherService gRPC service
type CredentialsFetcherServer struct {
	UnimplementedCredentialsFetcherServiceServer
	krbFilesDir     string
	awsSmSecretName string
	mu              sync.Mutex
	shutdownCh      chan struct{}
	krbClient       *kerberos.Client
	ldapClient      *ldap.Client
	shellExecutor   shell.Executor
}

// NewCredentialsFetcherServer creates a new instance of CredentialsFetcherServer
func NewCredentialsFetcherServer() *CredentialsFetcherServer {
	return &CredentialsFetcherServer{
		shutdownCh:    make(chan struct{}),
		krbClient:     kerberos.NewClient(),
		ldapClient:    ldap.NewClient(),
		shellExecutor: shell.NewExecutor(),
	}
}

// AddKerberosLease implements the AddKerberosLease RPC method
func (s *CredentialsFetcherServer) AddKerberosLease(ctx context.Context, req *CreateKerberosLeaseRequest) (*CreateKerberosLeaseResponse, error) {
	log.Info("Received AddKerberosLease request")

}

// AddNonDomainJoinedKerberosLease implements the AddNonDomainJoinedKerberosLease RPC method
func (s *CredentialsFetcherServer) AddNonDomainJoinedKerberosLease(ctx context.Context, req *CreateNonDomainJoinedKerberosLeaseRequest) (*CreateNonDomainJoinedKerberosLeaseResponse, error) {
	log.Info("Received AddNonDomainJoinedKerberosLease request")

}

// RenewNonDomainJoinedKerberosLease implements the RenewNonDomainJoinedKerberosLease RPC method
func (s *CredentialsFetcherServer) RenewNonDomainJoinedKerberosLease(ctx context.Context, req *RenewNonDomainJoinedKerberosLeaseRequest) (*RenewNonDomainJoinedKerberosLeaseResponse, error) {
	log.Info("Received RenewNonDomainJoinedKerberosLease request")

}

// DeleteKerberosLease implements the DeleteKerberosLease RPC method
func (s *CredentialsFetcherServer) DeleteKerberosLease(ctx context.Context, req *DeleteKerberosLeaseRequest) (*DeleteKerberosLeaseResponse, error) {
	log.Info("Received DeleteKerberosLease request")

}

// HealthCheck implements the HealthCheck RPC method
func (s *CredentialsFetcherServer) HealthCheck(ctx context.Context, req *HealthCheckRequest) (*HealthCheckResponse, error) {
	log.Info("Received HealthCheck request", "service", req.Service)

}

// AddKerberosArnLease implements the AddKerberosArnLease RPC method
func (s *CredentialsFetcherServer) AddKerberosArnLease(ctx context.Context, req *KerberosArnLeaseRequest) (*CreateKerberosArnLeaseResponse, error) {
	log.Info("Received AddKerberosArnLease request")

}

// RenewKerberosArnLease implements the RenewKerberosArnLease RPC method
func (s *CredentialsFetcherServer) RenewKerberosArnLease(ctx context.Context, req *RenewKerberosArnLeaseRequest) (*RenewKerberosArnLeaseResponse, error) {
	log.Info("Received RenewKerberosArnLease request")

}

// RunServer starts the gRPC server
func (s *CredentialsFetcherServer) RunServer(unixSocketDir string) error {
	// Create the socket directory if it doesn't exist
	if err := os.MkdirAll(unixSocketDir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %v", err)
	}

	// Create the socket path
	socketPath := filepath.Join(unixSocketDir, "credentials_fetcher.sock")

	// Remove existing socket file if it exists
	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("failed to remove existing socket file: %v", err)
		}
	}

	// Create the listener
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %v", err)
	}

	// Set permissions on the socket file
	if err := os.Chmod(socketPath, 0666); err != nil {
		return fmt.Errorf("failed to set permissions on socket file: %v", err)
	}

	// Create the gRPC server
	grpcServer := grpc.NewServer()
	RegisterCredentialsFetcherServiceServer(grpcServer, s)

	// Start the server in a goroutine
	go func() {
		log.Info("Starting gRPC server", "socket_path", socketPath)
		if err := grpcServer.Serve(lis); err != nil {
			log.Error("Failed to serve", "error", err)
		}
	}()

	// Wait for shutdown signal
	<-s.shutdownCh

	// Gracefully stop the server
	grpcServer.GracefulStop()

	return nil
}

// Shutdown signals the server to shut down
func (s *CredentialsFetcherServer) Shutdown() {
	close(s.shutdownCh)
}
