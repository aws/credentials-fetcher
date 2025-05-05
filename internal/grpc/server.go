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
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var log = logger.GetInstance()

// Server defines the interface for the gRPC server
type Server interface {
	RunServer(socketDir string) error
	Shutdown()
}

// CredentialsFetcherServer implements the CredentialsFetcherService gRPC service
type CredentialsFetcherServer struct {
	pb.UnimplementedCredentialsFetcherServiceServer
	krbFilesDir       string
	awsSecretsManager string
	mu                sync.Mutex
	shutdownCh        chan struct{}
	krbClient         *kerberos.Client
	ldapClient        *ldap.Client
	shellExecutor     cmdexec.Executor
}

// NewCredentialsFetcherServerFunc is the function type for creating a new server
type NewCredentialsFetcherServerFunc func(krbFilesDir, awsSecretsManager string) Server

// NewCredentialsFetcherServer is the default implementation for creating a new server
var NewCredentialsFetcherServer NewCredentialsFetcherServerFunc = func(krbFilesDir, awsSecretsManager string) Server {
	return &CredentialsFetcherServer{
		krbFilesDir:       krbFilesDir,
		awsSecretsManager: awsSecretsManager,
		shutdownCh:        make(chan struct{}),
		krbClient:         kerberos.NewClient(),
		ldapClient:        ldap.NewClient(),
		shellExecutor:     cmdexec.NewExecutor(),
	}
}

// AddKerberosLease implements the AddKerberosLease RPC method
func (s *CredentialsFetcherServer) AddKerberosLease(ctx context.Context, req *pb.CreateKerberosLeaseRequest) (*pb.CreateKerberosLeaseResponse, error) {
	log.Info("Received AddKerberosLease request")

	return &pb.CreateKerberosLeaseResponse{
		LeaseId:                  "",
		CreatedKerberosFilePaths: []string{},
	}, nil
}

// AddNonDomainJoinedKerberosLease implements the AddNonDomainJoinedKerberosLease RPC method
func (s *CredentialsFetcherServer) AddNonDomainJoinedKerberosLease(ctx context.Context, req *pb.CreateNonDomainJoinedKerberosLeaseRequest) (*pb.CreateNonDomainJoinedKerberosLeaseResponse, error) {
	log.Info("Received AddNonDomainJoinedKerberosLease request")
	return &pb.CreateNonDomainJoinedKerberosLeaseResponse{
		LeaseId:                  "",
		CreatedKerberosFilePaths: []string{},
	}, nil
}

// RenewNonDomainJoinedKerberosLease implements the RenewNonDomainJoinedKerberosLease RPC method
func (s *CredentialsFetcherServer) RenewNonDomainJoinedKerberosLease(ctx context.Context, req *pb.RenewNonDomainJoinedKerberosLeaseRequest) (*pb.RenewNonDomainJoinedKerberosLeaseResponse, error) {
	log.Info("Received RenewNonDomainJoinedKerberosLease request")
	return &pb.RenewNonDomainJoinedKerberosLeaseResponse{
		RenewedKerberosFilePaths: []string{},
	}, nil
}

// DeleteKerberosLease implements the DeleteKerberosLease RPC method
func (s *CredentialsFetcherServer) DeleteKerberosLease(ctx context.Context, req *pb.DeleteKerberosLeaseRequest) (*pb.DeleteKerberosLeaseResponse, error) {
	log.Info("Received DeleteKerberosLease request")
	return &pb.DeleteKerberosLeaseResponse{
		LeaseId:                  "",
		DeletedKerberosFilePaths: []string{},
	}, nil
}

// HealthCheck implements the HealthCheck RPC method
func (s *CredentialsFetcherServer) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	log.Info("Received HealthCheck request", "service", req.Service)

	// Perform basic health checks
	// 1. Check if the server is running (which it is if we're here)
	// 2. Check if we can access the krbFilesDir
	if _, err := os.Stat(s.krbFilesDir); os.IsNotExist(err) {
		log.Error("Health check failed: krbFilesDir does not exist", "dir", s.krbFilesDir)
		return nil, status.Errorf(codes.Internal, "Health check failed: krbFilesDir does not exist")
	}

	// Return OK status
	return &pb.HealthCheckResponse{Status: "OK"}, nil
}

// AddKerberosArnLease implements the AddKerberosArnLease RPC method
func (s *CredentialsFetcherServer) AddKerberosArnLease(ctx context.Context, req *pb.KerberosArnLeaseRequest) (*pb.CreateKerberosArnLeaseResponse, error) {
	log.Info("Received AddKerberosArnLease request")
	return &pb.CreateKerberosArnLeaseResponse{
		LeaseId:              "",
		KrbTicketResponseMap: []*pb.KerberosTicketArnResponse{},
	}, nil
}

// RenewKerberosArnLease implements the RenewKerberosArnLease RPC method
func (s *CredentialsFetcherServer) RenewKerberosArnLease(ctx context.Context, req *pb.RenewKerberosArnLeaseRequest) (*pb.RenewKerberosArnLeaseResponse, error) {
	log.Info("Received RenewKerberosArnLease request")
	return &pb.RenewKerberosArnLeaseResponse{
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
	pb.RegisterCredentialsFetcherServiceServer(grpcServer, s)

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
