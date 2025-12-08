package cgo

import (
	"testing"
)

// TestGetErrorMessage_NilContext tests that GetErrorMessage handles nil context gracefully
func TestGetErrorMessage_NilContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	// Test with nil context - should return a simple error code message
	result := wrapper.GetErrorMessage(nil, 12345)

	expected := "error code 12345"
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

// TestGetErrorMessage_ValidContext tests GetErrorMessage with a valid context
func TestGetErrorMessage_ValidContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	// Initialize a context
	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Failed to initialize context: %v", err)
	}
	defer wrapper.FreeContext(ctx)

	// Test with a valid context and a known error code
	// Error code -1765328203 is KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN
	result := wrapper.GetErrorMessage(ctx, -1765328203)

	// The result should contain more than just "error code"
	// It should have a descriptive message from krb5
	if result == "error code -1765328203" {
		t.Errorf("Expected descriptive error message from krb5, got simple error code")
	}

	// Verify it's not empty
	if result == "" {
		t.Errorf("Expected non-empty error message")
	}
}

// TestGetErrorMessage_ZeroCode tests GetErrorMessage with error code 0 (success)
func TestGetErrorMessage_ZeroCode(t *testing.T) {
	wrapper := NewCGOWrapper()

	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Failed to initialize context: %v", err)
	}
	defer wrapper.FreeContext(ctx)

	// Test with error code 0 (success/no error)
	result := wrapper.GetErrorMessage(ctx, 0)

	// Should return some message (likely "Success" or similar)
	if result == "" {
		t.Errorf("Expected non-empty message for error code 0")
	}
}

// TestGetErrorMessage_NilContextWithZeroCode tests nil context with zero error code
func TestGetErrorMessage_NilContextWithZeroCode(t *testing.T) {
	wrapper := NewCGOWrapper()

	result := wrapper.GetErrorMessage(nil, 0)

	expected := "error code 0"
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

// TestInitContext_Success tests successful context initialization
func TestInitContext_Success(t *testing.T) {
	wrapper := NewCGOWrapper()

	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Expected successful context initialization, got error: %v", err)
	}

	if ctx == nil {
		t.Error("Expected non-nil context")
	}

	// Clean up
	wrapper.FreeContext(ctx)
}

// TestNewCGOWrapper tests wrapper creation
func TestNewCGOWrapper(t *testing.T) {
	wrapper := NewCGOWrapper()

	if wrapper == nil {
		t.Error("Expected non-nil wrapper")
	}
}

// TestParseName_NilContext tests that ParseName handles nil context gracefully
func TestParseName_NilContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	_, err := wrapper.ParseName(nil, "test@EXAMPLE.COM")

	if err == nil {
		t.Error("Expected error when context is nil")
	}

	expectedError := "context is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestAllocCredOptions_NilContext tests that AllocCredOptions handles nil context gracefully
func TestAllocCredOptions_NilContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	_, err := wrapper.AllocCredOptions(nil)

	if err == nil {
		t.Error("Expected error when context is nil")
	}

	expectedError := "context is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestGetInitCredsPassword_NilContext tests that GetInitCredsPassword handles nil context gracefully
func TestGetInitCredsPassword_NilContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	_, err := wrapper.GetInitCredsPassword(nil, nil, "password", nil)

	if err == nil {
		t.Error("Expected error when context is nil")
	}

	expectedError := "context is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestGetInitCredsPassword_NilPrincipal tests that GetInitCredsPassword handles nil principal gracefully
func TestGetInitCredsPassword_NilPrincipal(t *testing.T) {
	wrapper := NewCGOWrapper()

	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Failed to initialize context: %v", err)
	}
	defer wrapper.FreeContext(ctx)

	_, err = wrapper.GetInitCredsPassword(ctx, nil, "password", nil)

	if err == nil {
		t.Error("Expected error when principal is nil")
	}

	expectedError := "principal is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestGetRenewedCreds_NilContext tests that GetRenewedCreds handles nil context gracefully
func TestGetRenewedCreds_NilContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	_, err := wrapper.GetRenewedCreds(nil, nil, nil)

	if err == nil {
		t.Error("Expected error when context is nil")
	}

	expectedError := "context is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestGetRenewedCreds_NilCache tests that GetRenewedCreds handles nil cache gracefully
func TestGetRenewedCreds_NilCache(t *testing.T) {
	wrapper := NewCGOWrapper()

	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Failed to initialize context: %v", err)
	}
	defer wrapper.FreeContext(ctx)

	_, err = wrapper.GetRenewedCreds(ctx, nil, nil)

	if err == nil {
		t.Error("Expected error when cache is nil")
	}

	expectedError := "cache is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestGetRenewedCreds_NilPrincipal tests that GetRenewedCreds handles nil principal gracefully
func TestGetRenewedCreds_NilPrincipal(t *testing.T) {
	wrapper := NewCGOWrapper()

	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Failed to initialize context: %v", err)
	}
	defer wrapper.FreeContext(ctx)

	// Create a mock cache (we won't actually use it, just need non-nil value)
	// Since we can't create a real cache without credentials, we'll just test with a string
	_, err = wrapper.GetRenewedCreds(ctx, "mock_cache", nil)

	if err == nil {
		t.Error("Expected error when principal is nil")
	}

	expectedError := "principal is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestGetPrincipal_NilContext tests that GetPrincipal handles nil context gracefully
func TestGetPrincipal_NilContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	_, err := wrapper.GetPrincipal(nil, nil)

	if err == nil {
		t.Error("Expected error when context is nil")
	}

	expectedError := "context is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestGetPrincipal_NilCache tests that GetPrincipal handles nil cache gracefully
func TestGetPrincipal_NilCache(t *testing.T) {
	wrapper := NewCGOWrapper()

	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Failed to initialize context: %v", err)
	}
	defer wrapper.FreeContext(ctx)

	_, err = wrapper.GetPrincipal(ctx, nil)

	if err == nil {
		t.Error("Expected error when cache is nil")
	}

	expectedError := "cache is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestResolveCache_NilContext tests that ResolveCache handles nil context gracefully
func TestResolveCache_NilContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	_, err := wrapper.ResolveCache(nil, "/tmp/test")

	if err == nil {
		t.Error("Expected error when context is nil")
	}

	expectedError := "context is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestDefaultCache_NilContext tests that DefaultCache handles nil context gracefully
func TestDefaultCache_NilContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	_, err := wrapper.DefaultCache(nil)

	if err == nil {
		t.Error("Expected error when context is nil")
	}

	expectedError := "context is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestInitializeCache_NilContext tests that InitializeCache handles nil context gracefully
func TestInitializeCache_NilContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	err := wrapper.InitializeCache(nil, nil, nil)

	if err == nil {
		t.Error("Expected error when context is nil")
	}

	expectedError := "context is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestInitializeCache_NilCache tests that InitializeCache handles nil cache gracefully
func TestInitializeCache_NilCache(t *testing.T) {
	wrapper := NewCGOWrapper()

	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Failed to initialize context: %v", err)
	}
	defer wrapper.FreeContext(ctx)

	err = wrapper.InitializeCache(ctx, nil, nil)

	if err == nil {
		t.Error("Expected error when cache is nil")
	}

	expectedError := "cache is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestInitializeCache_NilPrincipal tests that InitializeCache handles nil principal gracefully
func TestInitializeCache_NilPrincipal(t *testing.T) {
	wrapper := NewCGOWrapper()

	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Failed to initialize context: %v", err)
	}
	defer wrapper.FreeContext(ctx)

	err = wrapper.InitializeCache(ctx, "mock_cache", nil)

	if err == nil {
		t.Error("Expected error when principal is nil")
	}

	expectedError := "principal is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestStoreCred_NilContext tests that StoreCred handles nil context gracefully
func TestStoreCred_NilContext(t *testing.T) {
	wrapper := NewCGOWrapper()

	err := wrapper.StoreCred(nil, nil, nil)

	if err == nil {
		t.Error("Expected error when context is nil")
	}

	expectedError := "context is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestStoreCred_NilCache tests that StoreCred handles nil cache gracefully
func TestStoreCred_NilCache(t *testing.T) {
	wrapper := NewCGOWrapper()

	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Failed to initialize context: %v", err)
	}
	defer wrapper.FreeContext(ctx)

	err = wrapper.StoreCred(ctx, nil, nil)

	if err == nil {
		t.Error("Expected error when cache is nil")
	}

	expectedError := "cache is nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestStoreCred_NilCreds tests that StoreCred handles nil credentials gracefully
func TestStoreCred_NilCreds(t *testing.T) {
	wrapper := NewCGOWrapper()

	ctx, err := wrapper.InitContext()
	if err != nil {
		t.Fatalf("Failed to initialize context: %v", err)
	}
	defer wrapper.FreeContext(ctx)

	err = wrapper.StoreCred(ctx, "mock_cache", nil)

	if err == nil {
		t.Error("Expected error when credentials are nil")
	}

	expectedError := "credentials are nil"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}
