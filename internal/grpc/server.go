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
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"google.golang.org/grpc"
)

var log = logger.GetInstance()

// CredentialsFetcherServer implements the CredentialsFetcherService gRPC service
type CredentialsFetcherServer struct {
	UnimplementedCredentialsFetcherServiceServer
	krbFilesDir     string
	awsSmSecretName string
	mu              sync.Mutex
	shutdownCh      chan struct{}
	krbClient       *kerberos.Client
	ldapClient      *ldap.Client
	shellExecutor   cmdexec.Executor
}

// NewCredentialsFetcherServer creates a new instance of CredentialsFetcherServer
func NewCredentialsFetcherServer() *CredentialsFetcherServer {
	return &CredentialsFetcherServer{
		shutdownCh:    make(chan struct{}),
		krbClient:     kerberos.NewClient(),
		ldapClient:    ldap.NewClient(),
		shellExecutor: cmdexec.NewExecutor(),
	}
}

// AddKerberosLease implements the AddKerberosLease RPC method
func (s *CredentialsFetcherServer) AddKerberosLease(ctx context.Context, req *CreateKerberosLeaseRequest) (*CreateKerberosLeaseResponse, error) {
	log.Info("Received AddKerberosLease request")
	return &CreateKerberosLeaseResponse{
		LeaseId:                  "",
		CreatedKerberosFilePaths: []string{},
	}, nil
}

// AddNonDomainJoinedKerberosLease implements the AddNonDomainJoinedKerberosLease RPC method
func (s *CredentialsFetcherServer) AddNonDomainJoinedKerberosLease(ctx context.Context, req *CreateNonDomainJoinedKerberosLeaseRequest) (*CreateNonDomainJoinedKerberosLeaseResponse, error) {
	log.Info("Received AddNonDomainJoinedKerberosLease request")
	return &CreateNonDomainJoinedKerberosLeaseResponse{
		LeaseId:                  "",
		CreatedKerberosFilePaths: []string{},
	}, nil
}

// RenewNonDomainJoinedKerberosLease implements the RenewNonDomainJoinedKerberosLease RPC method
func (s *CredentialsFetcherServer) RenewNonDomainJoinedKerberosLease(ctx context.Context, req *RenewNonDomainJoinedKerberosLeaseRequest) (*RenewNonDomainJoinedKerberosLeaseResponse, error) {
	log.Info("Received RenewNonDomainJoinedKerberosLease request")
	return &RenewNonDomainJoinedKerberosLeaseResponse{
		RenewedKerberosFilePaths: []string{},
	}, nil
}

// DeleteKerberosLease implements the DeleteKerberosLease RPC method
func (s *CredentialsFetcherServer) DeleteKerberosLease(ctx context.Context, req *DeleteKerberosLeaseRequest) (*DeleteKerberosLeaseResponse, error) {
	log.Info("Received DeleteKerberosLease request")
	return &DeleteKerberosLeaseResponse{
		LeaseId:                  "",
		DeletedKerberosFilePaths: []string{},
	}, nil
}

// HealthCheck implements the HealthCheck RPC method
func (s *CredentialsFetcherServer) HealthCheck(ctx context.Context, req *HealthCheckRequest) (*HealthCheckResponse, error) {
	log.Info("Received HealthCheck request", "service", req.Service)
	return &HealthCheckResponse{Status: "OK"}, nil
}

// AddKerberosArnLease implements the AddKerberosArnLease RPC method
func (s *CredentialsFetcherServer) AddKerberosArnLease(ctx context.Context, req *KerberosArnLeaseRequest) (*CreateKerberosArnLeaseResponse, error) {
	log.Info("Received AddKerberosArnLease request")
	return &CreateKerberosArnLeaseResponse{
		LeaseId:              "",
		KrbTicketResponseMap: []*KerberosTicketArnResponse{},
	}, nil
}

// RenewKerberosArnLease implements the RenewKerberosArnLease RPC method
func (s *CredentialsFetcherServer) RenewKerberosArnLease(ctx context.Context, req *RenewKerberosArnLeaseRequest) (*RenewKerberosArnLeaseResponse, error) {
	log.Info("Received RenewKerberosArnLease request")
	return &RenewKerberosArnLeaseResponse{
		Status: "OK",
	}, nil
}

// RunServer starts the gRPC server
func (s *CredentialsFetcherServer) RunServer(unixSocketDir string) error {

	socketPath := filepath.Join(unixSocketDir, "credentials_fetcher.sock")

	// Remove existing socket file if it exists
	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("failed to remove existing socket file: %v", err)
		}
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %v", err)
	}

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
