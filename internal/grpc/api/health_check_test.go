package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
)

// TestHealthCheckHandler tests the HealthCheck handler
func TestHealthCheckHandler(t *testing.T) {
	// Create handler
	handler := NewHealthCheckHandler()

	// Create request
	req := &pb.HealthCheckRequest{
		Service: "test-service",
	}

	// Call the method
	resp, err := handler.HealthCheck(context.Background(), req)

	// Check results
	assert.NoError(t, err)
	assert.NotNil(t, resp)
}

// TestNewHealthCheckHandler tests the NewHealthCheckHandler function
func TestNewHealthCheckHandler(t *testing.T) {
	// Create handler
	handler := NewHealthCheckHandler()

	// Check that it's not nil
	assert.NotNil(t, handler)
}
