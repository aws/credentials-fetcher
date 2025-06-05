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
	"golang.a2z.com/CredentialsFetcherV2/internal/grpc/api"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"google.golang.org/grpc"
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
	krbFilesDir     string
	awsSMSecretName string
	mu              sync.Mutex
	shutdownCh      chan struct{}
	krbClient       *kerberos.Client
	ldapClient      *ldap.Client
	shellExecutor   cmdexec.Executor

	// API handlers
	nonDomainJoinedHandler  *api.NonDomainJoinedKerberosHandler
	domainJoinedHandler     *api.DomainJoinedKerberosLeaseHandler
	healthCheckHandler      *api.HealthCheckHandler
	kerberosLeaseHandler    *api.KerberosLeaseHandler
	kerberosArnLeaseHandler *api.KerberosArnLeaseHandler
}

// NewCredentialsFetcherServerFunc is the function type for creating a new server
type NewCredentialsFetcherServerFunc func(krbFilesDir, awsSMSecretName string) Server

// NewCredentialsFetcherServer is the default implementation for creating a new server
var NewCredentialsFetcherServer NewCredentialsFetcherServerFunc = func(krbFilesDir, awsSMSecretName string) Server {
	krbClient := kerberos.NewClient()
	ldapClient := ldap.NewClient()
	shellExecutor := cmdexec.NewExecutor()

	return &CredentialsFetcherServer{
		krbFilesDir:     krbFilesDir,
		awsSMSecretName: awsSMSecretName,
		shutdownCh:      make(chan struct{}),
		krbClient:       krbClient,
		ldapClient:      ldapClient,
		shellExecutor:   shellExecutor,

		// Initialize API handlers
		nonDomainJoinedHandler:  api.NewNonDomainJoinedKerberosHandler(krbFilesDir, awsSMSecretName, krbClient, ldapClient, shellExecutor),
		domainJoinedHandler:     api.NewDomainJoinedKerberosLeaseHandler(krbFilesDir, awsSMSecretName, krbClient),
		healthCheckHandler:      api.NewHealthCheckHandler(),
		kerberosLeaseHandler:    api.NewKerberosLeaseHandler(krbFilesDir, krbClient),
		kerberosArnLeaseHandler: api.NewKerberosArnLeaseHandler(krbFilesDir, krbClient, shellExecutor),
	}
}

// AddKerberosLease implements the AddKerberosLease RPC method
func (s *CredentialsFetcherServer) AddKerberosLease(ctx context.Context, req *pb.CreateKerberosLeaseRequest) (*pb.CreateKerberosLeaseResponse, error) {
	log.Info("Received AddDomainJoinedKerberosLease request")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.domainJoinedHandler.AddKerberosLease(ctx, req)
}

// AddNonDomainJoinedKerberosLease implements the AddNonDomainJoinedKerberosLease RPC method
func (s *CredentialsFetcherServer) AddNonDomainJoinedKerberosLease(ctx context.Context, req *pb.CreateNonDomainJoinedKerberosLeaseRequest) (*pb.CreateNonDomainJoinedKerberosLeaseResponse, error) {
	log.Info("Received AddNonDomainJoinedKerberosLease request")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nonDomainJoinedHandler.AddNonDomainJoinedKerberosLease(ctx, req)
}

// RenewNonDomainJoinedKerberosLease implements the RenewNonDomainJoinedKerberosLease RPC method
func (s *CredentialsFetcherServer) RenewNonDomainJoinedKerberosLease(ctx context.Context, req *pb.RenewNonDomainJoinedKerberosLeaseRequest) (*pb.RenewNonDomainJoinedKerberosLeaseResponse, error) {
	log.Info("Received RenewNonDomainJoinedKerberosLease request")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nonDomainJoinedHandler.RenewNonDomainJoinedKerberosLease(ctx, req)
}

// DeleteKerberosLease implements the DeleteKerberosLease RPC method
func (s *CredentialsFetcherServer) DeleteKerberosLease(ctx context.Context, req *pb.DeleteKerberosLeaseRequest) (*pb.DeleteKerberosLeaseResponse, error) {
	log.Info("Received DeleteKerberosLease request")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kerberosLeaseHandler.DeleteKerberosLease(ctx, req)
}

// HealthCheck implements the HealthCheck RPC method
func (s *CredentialsFetcherServer) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	log.Info("Received HealthCheck request")
	return s.healthCheckHandler.HealthCheck(ctx, req)
}

// AddKerberosArnLease implements the AddKerberosArnLease RPC method
func (s *CredentialsFetcherServer) AddKerberosArnLease(ctx context.Context, req *pb.KerberosArnLeaseRequest) (*pb.CreateKerberosArnLeaseResponse, error) {
	log.Info("Received AddKerberosArnLease request")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kerberosArnLeaseHandler.AddKerberosArnLease(ctx, req)
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
