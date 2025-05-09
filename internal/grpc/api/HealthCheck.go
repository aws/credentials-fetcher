package api

import (
	"context"

	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
)

// HealthCheckHandler handles health check operations
type HealthCheckHandler struct{}

// NewHealthCheckHandler creates a new handler for health check operations
func NewHealthCheckHandler() *HealthCheckHandler {
	return &HealthCheckHandler{}
}

// HealthCheck implements the HealthCheck RPC method
func (h *HealthCheckHandler) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	log.Info("Received HealthCheck request", "service", req.Service)

	// Perform basic health checks
	// The server is running if we're here, which is sufficient for a health check

	// Return OK status
	return &pb.HealthCheckResponse{Status: "OK"}, nil
}
