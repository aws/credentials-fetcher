package kerberos

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	assert.NotNil(t, client)
}

func TestGetTicketInfo_PathValidation(t *testing.T) {
	client := NewClient()

	// Test relative path
	_, err := client.GetTicketInfo("relative/path")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "path must be absolute")

	// Test non-existent file
	_, err = client.GetTicketInfo("/nonexistent/file")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stat file")
}

func TestGetTicketFromCache_PathValidation(t *testing.T) {
	client := NewClient()

	// Test relative path
	_, err := client.GetTicketFromCache("relative/path")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "path must be absolute")

	// Test non-existent file
	_, err = client.GetTicketFromCache("/nonexistent/file")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stat file")
}
