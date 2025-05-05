package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/constants"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// CredentialsFetcherClient is a client for the CredentialsFetcher service
type CredentialsFetcherClient struct {
	conn    *grpc.ClientConn
	timeout time.Duration
}

// NewCredentialsFetcherClient creates a new CredentialsFetcherClient
func NewCredentialsFetcherClient(conn *grpc.ClientConn, timeout time.Duration) *CredentialsFetcherClient {
	return &CredentialsFetcherClient{
		conn:    conn,
		timeout: timeout,
	}
}

// GetGrpcClientConnection returns a gRPC client connection
func GetGrpcClientConnection(socketPath string) (*grpc.ClientConn, error) {
	address := fmt.Sprintf("unix:%s", socketPath)

	// Check if the socket file exists
	if _, err := os.Stat(socketPath); err != nil {
		log.Printf("Could not find credentials fetcher socket at %s: %v", socketPath, err)
		return nil, err
	}

	// Connect to the server
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Could not initialize client connection: %v", err)
		return nil, err
	}
	return conn, nil
}

// HealthCheck invokes the credentials fetcher daemon to check its health status
func (c *CredentialsFetcherClient) HealthCheck(ctx context.Context, serviceName string) (string, error) {
	if len(serviceName) == 0 {
		return "", status.Errorf(codes.InvalidArgument, "service name should not be empty")
	}

	client := pb.NewCredentialsFetcherServiceClient(c.conn)
	request := &pb.HealthCheckRequest{Service: serviceName}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	response, err := client.HealthCheck(ctx, request)
	if err != nil {
		log.Printf("Credentials-fetcher daemon status is unhealthy during health check: %v", err)
		return "", err
	}
	log.Printf("Credentials-fetcher daemon is running")

	return response.GetStatus(), nil
}

func main() {
	// Define command line flags
	socketPath := flag.String("socket", constants.DefaultSocketDir+"/credentials_fetcher.sock", "Path to the Unix socket")
	serviceName := flag.String("service", "health-check-client", "Service name to include in the health check request")
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout for the health check request")
	flag.Parse()

	// Get gRPC client connection
	conn, err := GetGrpcClientConnection(*socketPath)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Create client
	client := NewCredentialsFetcherClient(conn, *timeout)

	// Perform health check
	status, err := client.HealthCheck(context.Background(), *serviceName)
	if err != nil {
		log.Fatalf("Health check failed: %v", err)
	}

	// Print the response
	fmt.Printf("Health check status: %s\n", status)
	fmt.Println("Health check successful!")
}
