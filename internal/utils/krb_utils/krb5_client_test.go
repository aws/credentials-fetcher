package krb_utils

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockKrb5Wrapper is a mock implementation of Krb5Wrapper for testing
type mockKrb5Wrapper struct {
	initContextFunc          func() (Krb5Context, error)
	freeContextFunc          func(ctx Krb5Context)
	parseNameFunc            func(ctx Krb5Context, principal string) (Krb5Principal, error)
	freePrincipalFunc        func(ctx Krb5Context, princ Krb5Principal)
	allocCredOptionsFunc     func(ctx Krb5Context) (Krb5CredOptions, error)
	freeCredOptionsFunc      func(ctx Krb5Context, opts Krb5CredOptions)
	setForwardableFunc       func(opts Krb5CredOptions, value bool)
	setProxiableFunc         func(opts Krb5CredOptions, value bool)
	setTicketLifetimeFunc    func(opts Krb5CredOptions, lifetime int32)
	setRenewableLifeFunc     func(opts Krb5CredOptions, lifetime int32)
	getInitCredsPasswordFunc func(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error)
	getRenewedCredsFunc      func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error)
	freeCredContentsFunc     func(ctx Krb5Context, creds Krb5Creds)
	resolveCacheFunc         func(ctx Krb5Context, cachePath string) (Krb5Ccache, error)
	defaultCacheFunc         func(ctx Krb5Context) (Krb5Ccache, error)
	getCacheNameFunc         func(ctx Krb5Context, cache Krb5Ccache) string
	closeCacheFunc           func(ctx Krb5Context, cache Krb5Ccache)
	getPrincipalFunc         func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error)
	initializeCacheFunc      func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error
	storeCredFunc            func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error
	getErrorMessageFunc      func(ctx Krb5Context, code int) string
	runKlistFunc             func(ccachePath string) error
	mkdirAllFunc             func(path string, perm os.FileMode) error
	chmodFunc                func(path string, mode os.FileMode) error
	statFunc                 func(path string) (os.FileInfo, error)
}

func (m *mockKrb5Wrapper) InitContext() (Krb5Context, error) {
	if m.initContextFunc != nil {
		return m.initContextFunc()
	}
	return "mock-context", nil
}

func (m *mockKrb5Wrapper) FreeContext(ctx Krb5Context) {
	if m.freeContextFunc != nil {
		m.freeContextFunc(ctx)
	}
}

func (m *mockKrb5Wrapper) ParseName(ctx Krb5Context, principal string) (Krb5Principal, error) {
	if m.parseNameFunc != nil {
		return m.parseNameFunc(ctx, principal)
	}
	return "mock-principal", nil
}

func (m *mockKrb5Wrapper) FreePrincipal(ctx Krb5Context, princ Krb5Principal) {
	if m.freePrincipalFunc != nil {
		m.freePrincipalFunc(ctx, princ)
	}
}

func (m *mockKrb5Wrapper) AllocCredOptions(ctx Krb5Context) (Krb5CredOptions, error) {
	if m.allocCredOptionsFunc != nil {
		return m.allocCredOptionsFunc(ctx)
	}
	return "mock-options", nil
}

func (m *mockKrb5Wrapper) FreeCredOptions(ctx Krb5Context, opts Krb5CredOptions) {
	if m.freeCredOptionsFunc != nil {
		m.freeCredOptionsFunc(ctx, opts)
	}
}

func (m *mockKrb5Wrapper) SetForwardable(opts Krb5CredOptions, value bool) {
	if m.setForwardableFunc != nil {
		m.setForwardableFunc(opts, value)
	}
}

func (m *mockKrb5Wrapper) SetProxiable(opts Krb5CredOptions, value bool) {
	if m.setProxiableFunc != nil {
		m.setProxiableFunc(opts, value)
	}
}

func (m *mockKrb5Wrapper) SetTicketLifetime(opts Krb5CredOptions, lifetime int32) {
	if m.setTicketLifetimeFunc != nil {
		m.setTicketLifetimeFunc(opts, lifetime)
	}
}

func (m *mockKrb5Wrapper) SetRenewableLife(opts Krb5CredOptions, lifetime int32) {
	if m.setRenewableLifeFunc != nil {
		m.setRenewableLifeFunc(opts, lifetime)
	}
}

func (m *mockKrb5Wrapper) GetInitCredsPassword(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error) {
	if m.getInitCredsPasswordFunc != nil {
		return m.getInitCredsPasswordFunc(ctx, princ, password, opts)
	}
	return "mock-creds", nil
}

func (m *mockKrb5Wrapper) GetRenewedCreds(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
	if m.getRenewedCredsFunc != nil {
		return m.getRenewedCredsFunc(ctx, cache, princ)
	}
	return &struct{}{}, nil
}

func (m *mockKrb5Wrapper) FreeCredContents(ctx Krb5Context, creds Krb5Creds) {
	if m.freeCredContentsFunc != nil {
		m.freeCredContentsFunc(ctx, creds)
	}
}

func (m *mockKrb5Wrapper) GetPrincipal(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
	if m.getPrincipalFunc != nil {
		return m.getPrincipalFunc(ctx, cache)
	}
	return &struct{}{}, nil
}

func (m *mockKrb5Wrapper) ResolveCache(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
	if m.resolveCacheFunc != nil {
		return m.resolveCacheFunc(ctx, cachePath)
	}
	return "mock-cache", nil
}

func (m *mockKrb5Wrapper) DefaultCache(ctx Krb5Context) (Krb5Ccache, error) {
	if m.defaultCacheFunc != nil {
		return m.defaultCacheFunc(ctx)
	}
	return "mock-cache", nil
}

func (m *mockKrb5Wrapper) GetCacheName(ctx Krb5Context, cache Krb5Ccache) string {
	if m.getCacheNameFunc != nil {
		return m.getCacheNameFunc(ctx, cache)
	}
	return "/tmp/krb5cc_mock"
}

func (m *mockKrb5Wrapper) CloseCache(ctx Krb5Context, cache Krb5Ccache) {
	if m.closeCacheFunc != nil {
		m.closeCacheFunc(ctx, cache)
	}
}

func (m *mockKrb5Wrapper) InitializeCache(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
	if m.initializeCacheFunc != nil {
		return m.initializeCacheFunc(ctx, cache, princ)
	}
	return nil
}

func (m *mockKrb5Wrapper) StoreCred(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
	if m.storeCredFunc != nil {
		return m.storeCredFunc(ctx, cache, creds)
	}
	return nil
}

func (m *mockKrb5Wrapper) GetErrorMessage(ctx Krb5Context, code int) string {
	if m.getErrorMessageFunc != nil {
		return m.getErrorMessageFunc(ctx, code)
	}
	return "mock error"
}

func (m *mockKrb5Wrapper) RunKlist(ccachePath string) error {
	if m.runKlistFunc != nil {
		return m.runKlistFunc(ccachePath)
	}
	return nil
}

func (m *mockKrb5Wrapper) MkdirAll(path string, perm os.FileMode) error {
	if m.mkdirAllFunc != nil {
		return m.mkdirAllFunc(path, perm)
	}
	return nil
}

func (m *mockKrb5Wrapper) Chmod(path string, mode os.FileMode) error {
	if m.chmodFunc != nil {
		return m.chmodFunc(path, mode)
	}
	return nil
}

func (m *mockKrb5Wrapper) Stat(path string) (os.FileInfo, error) {
	if m.statFunc != nil {
		return m.statFunc(path)
	}
	return nil, os.ErrNotExist
}

func TestKrb5Client_GenerateTicket_MissingPrincipal(t *testing.T) {
	mock := &mockKrb5Wrapper{}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Password:   "password123",
		CCachePath: "/tmp/krb5cc_test",
	}

	err := client.GenerateTicket(config)
	if err == nil {
		t.Error("Expected error for missing principal")
	}
	if err.Error() != "principal is required" {
		t.Errorf("Expected 'principal is required', got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_MissingPassword(t *testing.T) {
	mock := &mockKrb5Wrapper{}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal:  "test@EXAMPLE.COM",
		CCachePath: "/tmp/krb5cc_test",
	}

	err := client.GenerateTicket(config)
	if err == nil {
		t.Error("Expected error for missing password")
	}
	if err.Error() != "password is required" {
		t.Errorf("Expected 'password is required', got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_MissingCachePath(t *testing.T) {
	mock := &mockKrb5Wrapper{}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal: "test@EXAMPLE.COM",
		Password:  "password123",
	}

	err := client.GenerateTicket(config)
	if err == nil {
		t.Error("Expected error for missing cache path")
	}
	if err.Error() != "cache path is required" {
		t.Errorf("Expected 'cache path is required', got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_InitContextError(t *testing.T) {
	mock := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return nil, errors.New("failed to init context")
		},
	}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal:  "test@EXAMPLE.COM",
		Password:   "password123",
		CCachePath: "/tmp/krb5cc_test",
		Verify:     false,
	}

	err := client.GenerateTicket(config)
	if err == nil {
		t.Error("Expected error from init context")
	}
	if !contains(err.Error(), "failed to initialize krb5 context") {
		t.Errorf("Expected init context error, got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_ParseNameError(t *testing.T) {
	mock := &mockKrb5Wrapper{
		parseNameFunc: func(ctx Krb5Context, principal string) (Krb5Principal, error) {
			return nil, errors.New("invalid principal")
		},
	}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal:  "invalid-principal",
		Password:   "password123",
		CCachePath: "/tmp/krb5cc_test",
		Verify:     false,
	}

	err := client.GenerateTicket(config)
	if err == nil {
		t.Error("Expected error from parse name")
	}
	if !contains(err.Error(), "failed to parse principal") {
		t.Errorf("Expected parse principal error, got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_AllocCredOptionsError(t *testing.T) {
	mock := &mockKrb5Wrapper{
		allocCredOptionsFunc: func(ctx Krb5Context) (Krb5CredOptions, error) {
			return nil, errors.New("failed to allocate options")
		},
	}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal:  "test@EXAMPLE.COM",
		Password:   "password123",
		CCachePath: "/tmp/krb5cc_test",
		Verify:     false,
	}

	err := client.GenerateTicket(config)
	if err == nil {
		t.Error("Expected error from alloc cred options")
	}
	if !contains(err.Error(), "failed to allocate credential options") {
		t.Errorf("Expected alloc cred options error, got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_AuthenticationFailure(t *testing.T) {
	mock := &mockKrb5Wrapper{
		getInitCredsPasswordFunc: func(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error) {
			return nil, errors.New("authentication failed")
		},
	}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal:  "test@EXAMPLE.COM",
		Password:   "wrongpassword",
		CCachePath: "/tmp/krb5cc_test",
		Verify:     false,
	}

	err := client.GenerateTicket(config)
	if err == nil {
		t.Error("Expected authentication error")
	}
	if !contains(err.Error(), "failed to authenticate") {
		t.Errorf("Expected authentication error, got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_ResolveCacheError(t *testing.T) {
	mock := &mockKrb5Wrapper{
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return nil, errors.New("failed to resolve cache")
		},
	}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal:  "test@EXAMPLE.COM",
		Password:   "password123",
		CCachePath: "/tmp/krb5cc_test",
		Verify:     false,
	}

	err := client.GenerateTicket(config)
	if err == nil {
		t.Error("Expected cache resolve error")
	}
	if !contains(err.Error(), "failed to resolve cache") {
		t.Errorf("Expected cache resolve error, got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_InitializeCacheError(t *testing.T) {
	mock := &mockKrb5Wrapper{
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
			return errors.New("failed to initialize cache")
		},
	}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal:  "test@EXAMPLE.COM",
		Password:   "password123",
		CCachePath: "/tmp/krb5cc_test",
		Verify:     false,
	}

	err := client.GenerateTicket(config)
	if err == nil {
		t.Error("Expected cache initialize error")
	}
	if !contains(err.Error(), "failed to initialize cache") {
		t.Errorf("Expected cache initialize error, got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_StoreCredError(t *testing.T) {
	mock := &mockKrb5Wrapper{
		storeCredFunc: func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
			return errors.New("failed to store credentials")
		},
	}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal:  "test@EXAMPLE.COM",
		Password:   "password123",
		CCachePath: "/tmp/krb5cc_test",
		Verify:     false,
	}

	err := client.GenerateTicket(config)
	if err == nil {
		t.Error("Expected store cred error")
	}
	if !contains(err.Error(), "failed to store credentials") {
		t.Errorf("Expected store cred error, got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_WithAllOptions(t *testing.T) {
	optionsCalled := make(map[string]bool)

	tmpDir := t.TempDir()
	cachePath := tmpDir + "/krb5cc_test"

	mock := &mockKrb5Wrapper{
		setForwardableFunc: func(opts Krb5CredOptions, value bool) {
			optionsCalled["forwardable"] = value
		},
		setProxiableFunc: func(opts Krb5CredOptions, value bool) {
			optionsCalled["proxiable"] = value
		},
		setTicketLifetimeFunc: func(opts Krb5CredOptions, lifetime int32) {
			if lifetime == 3600 {
				optionsCalled["lifetime"] = true
			}
		},
		setRenewableLifeFunc: func(opts Krb5CredOptions, lifetime int32) {
			if lifetime == 86400 {
				optionsCalled["renewable"] = true
			}
		},
	}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal:     "test@EXAMPLE.COM",
		Password:      "password123",
		CCachePath:    cachePath,
		Forwardable:   true,
		Proxiable:     true,
		Lifetime:      3600,
		RenewableLife: 86400,
		Verify:        false,
	}

	err := client.GenerateTicket(config)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if !optionsCalled["forwardable"] {
		t.Error("Expected forwardable to be set to true")
	}
	if !optionsCalled["proxiable"] {
		t.Error("Expected proxiable to be set to true")
	}
	if !optionsCalled["lifetime"] {
		t.Error("Expected lifetime to be set")
	}
	if !optionsCalled["renewable"] {
		t.Error("Expected renewable life to be set")
	}
}

func TestKrb5Client_VerifyTicket_Success(t *testing.T) {
	mock := &mockKrb5Wrapper{
		runKlistFunc: func(ccachePath string) error {
			return nil
		},
	}
	client := NewKrb5Client(mock)

	err := client.VerifyTicket("/tmp/krb5cc_test")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

func TestKrb5Client_VerifyTicket_Failure(t *testing.T) {
	mock := &mockKrb5Wrapper{
		runKlistFunc: func(ccachePath string) error {
			return errors.New("klist failed")
		},
	}
	client := NewKrb5Client(mock)

	err := client.VerifyTicket("/tmp/krb5cc_test")
	if err == nil {
		t.Error("Expected klist error")
	}
	if !contains(err.Error(), "klist failed") {
		t.Errorf("Expected klist failed error, got: %v", err)
	}
}

func TestKrb5Client_GenerateTicket_Success(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := tmpDir + "/krb5cc_test"

	mock := &mockKrb5Wrapper{}
	client := NewKrb5Client(mock)

	config := &KinitConfig{
		Principal:   "test@EXAMPLE.COM",
		Password:    "password123",
		CCachePath:  cachePath,
		Forwardable: true,
		Verify:      false, // Don't verify to avoid running real klist
	}

	err := client.GenerateTicket(config)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify directory was created via mock
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			len(s) > len(substr)+1 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Additional tests to reach 100% coverage

// Test verbose output and default cache path
func TestKrb5Client_GenerateTicket_VerbosePaths(t *testing.T) {
	t.Run("verbose with explicit cache path", func(t *testing.T) {
		mockWrapper := &mockKrb5Wrapper{
			initContextFunc:      func() (Krb5Context, error) { return "ctx", nil },
			parseNameFunc:        func(ctx Krb5Context, principal string) (Krb5Principal, error) { return "princ", nil },
			allocCredOptionsFunc: func(ctx Krb5Context) (Krb5CredOptions, error) { return "opts", nil },
			getInitCredsPasswordFunc: func(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error) {
				return "creds", nil
			},
			resolveCacheFunc:    func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) { return "cache", nil },
			initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error { return nil },
			storeCredFunc:       func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error { return nil },
			mkdirAllFunc:        func(path string, perm os.FileMode) error { return nil },
			statFunc:            func(path string) (os.FileInfo, error) { return nil, os.ErrNotExist },
			runKlistFunc:        func(ccachePath string) error { return nil },
		}

		client := NewKrb5Client(mockWrapper)
		config := &KinitConfig{
			Principal:  "user@EXAMPLE.COM",
			Password:   "password",
			CCachePath: "/tmp/krb5cc_test",
			Verbose:    true,
			Verify:     true,
		}

		err := client.GenerateTicket(config)
		assert.NoError(t, err)
	})
}

// Test chmod path when file exists
func TestKrb5Client_GenerateTicket_ChmodWhenFileExists(t *testing.T) {
	chmodCalled := false
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc:      func() (Krb5Context, error) { return "ctx", nil },
		parseNameFunc:        func(ctx Krb5Context, principal string) (Krb5Principal, error) { return "princ", nil },
		allocCredOptionsFunc: func(ctx Krb5Context) (Krb5CredOptions, error) { return "opts", nil },
		getInitCredsPasswordFunc: func(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error) {
			return "creds", nil
		},
		resolveCacheFunc:    func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) { return "cache", nil },
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error { return nil },
		storeCredFunc:       func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error { return nil },
		mkdirAllFunc:        func(path string, perm os.FileMode) error { return nil },
		statFunc: func(path string) (os.FileInfo, error) {
			// Return nil error to indicate file exists
			return nil, nil
		},
		chmodFunc: func(path string, mode os.FileMode) error {
			chmodCalled = true
			return nil
		},
	}

	client := NewKrb5Client(mockWrapper)
	config := &KinitConfig{
		Principal:  "user@EXAMPLE.COM",
		Password:   "password",
		CCachePath: "/tmp/krb5cc_test",
	}

	err := client.GenerateTicket(config)
	assert.NoError(t, err)
	assert.True(t, chmodCalled, "chmod should have been called when file exists")
}

// Test KEYRING path (chmod should not be attempted)
func TestKrb5Client_GenerateTicket_KeyringPath(t *testing.T) {
	chmodCalled := false
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc:      func() (Krb5Context, error) { return "ctx", nil },
		parseNameFunc:        func(ctx Krb5Context, principal string) (Krb5Principal, error) { return "princ", nil },
		allocCredOptionsFunc: func(ctx Krb5Context) (Krb5CredOptions, error) { return "opts", nil },
		getInitCredsPasswordFunc: func(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error) {
			return "creds", nil
		},
		resolveCacheFunc:    func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) { return "cache", nil },
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error { return nil },
		storeCredFunc:       func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error { return nil },
		mkdirAllFunc:        func(path string, perm os.FileMode) error { return nil },
		chmodFunc: func(path string, mode os.FileMode) error {
			chmodCalled = true
			return nil
		},
	}

	client := NewKrb5Client(mockWrapper)
	config := &KinitConfig{
		Principal:  "user@EXAMPLE.COM",
		Password:   "password",
		CCachePath: "KEYRING:persistent:1000",
	}

	err := client.GenerateTicket(config)
	assert.NoError(t, err)
	assert.False(t, chmodCalled, "chmod should not be called for KEYRING path")
}

// Test getDir edge cases
func TestGetDir(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "normal path", path: "/tmp/test/file.txt", expected: "/tmp/test"},
		{name: "root file", path: "/file.txt", expected: "/"},
		{name: "no slash", path: "file.txt", expected: "."},
		{name: "trailing slash", path: "/tmp/test/", expected: "/tmp/test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDir(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test mkdir failure
func TestKrb5Client_GenerateTicket_MkdirFailure(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc:      func() (Krb5Context, error) { return "ctx", nil },
		parseNameFunc:        func(ctx Krb5Context, principal string) (Krb5Principal, error) { return "princ", nil },
		allocCredOptionsFunc: func(ctx Krb5Context) (Krb5CredOptions, error) { return "opts", nil },
		getInitCredsPasswordFunc: func(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error) {
			return "creds", nil
		},
		mkdirAllFunc: func(path string, perm os.FileMode) error {
			return fmt.Errorf("permission denied")
		},
	}

	client := NewKrb5Client(mockWrapper)
	config := &KinitConfig{
		Principal:  "user@EXAMPLE.COM",
		Password:   "password",
		CCachePath: "/tmp/krb5cc_test",
	}

	err := client.GenerateTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create directory")
}

// Test chmod failure
func TestKrb5Client_GenerateTicket_ChmodFailure(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc:      func() (Krb5Context, error) { return "ctx", nil },
		parseNameFunc:        func(ctx Krb5Context, principal string) (Krb5Principal, error) { return "princ", nil },
		allocCredOptionsFunc: func(ctx Krb5Context) (Krb5CredOptions, error) { return "opts", nil },
		getInitCredsPasswordFunc: func(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error) {
			return "creds", nil
		},
		resolveCacheFunc:    func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) { return "cache", nil },
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error { return nil },
		storeCredFunc:       func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error { return nil },
		mkdirAllFunc:        func(path string, perm os.FileMode) error { return nil },
		statFunc:            func(path string) (os.FileInfo, error) { return nil, nil },
		chmodFunc:           func(path string, mode os.FileMode) error { return fmt.Errorf("permission denied") },
	}

	client := NewKrb5Client(mockWrapper)
	config := &KinitConfig{Principal: "user@EXAMPLE.COM", Password: "password", CCachePath: "/tmp/krb5cc_test"}

	err := client.GenerateTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to set permissions")
}

// Test ticket verification failure path (line 110-112)
func TestKrb5Client_GenerateTicket_VerifyFailure(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc:      func() (Krb5Context, error) { return "ctx", nil },
		parseNameFunc:        func(ctx Krb5Context, principal string) (Krb5Principal, error) { return "princ", nil },
		allocCredOptionsFunc: func(ctx Krb5Context) (Krb5CredOptions, error) { return "opts", nil },
		getInitCredsPasswordFunc: func(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error) {
			return "creds", nil
		},
		resolveCacheFunc:    func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) { return "cache", nil },
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error { return nil },
		storeCredFunc:       func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error { return nil },
		mkdirAllFunc:        func(path string, perm os.FileMode) error { return nil },
		statFunc:            func(path string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		runKlistFunc: func(ccachePath string) error {
			return errors.New("klist verification failed")
		},
	}

	client := NewKrb5Client(mockWrapper)
	config := &KinitConfig{
		Principal:  "user@EXAMPLE.COM",
		Password:   "password",
		CCachePath: "/tmp/krb5cc_test",
		Verify:     true, // Enable verification
	}

	err := client.GenerateTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ticket verification failed")
}

func TestKrb5Client_RenewTicket_Success(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(200), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		getPrincipalFunc: func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
			return Krb5Principal(300), nil
		},
		freePrincipalFunc: func(ctx Krb5Context, princ Krb5Principal) {},
		getRenewedCredsFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
			return Krb5Creds(400), nil
		},
		freeCredContentsFunc: func(ctx Krb5Context, creds Krb5Creds) {},
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
			return nil
		},
		storeCredFunc: func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
			return nil
		},
		runKlistFunc: func(ccachePath string) error {
			return nil
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
		Verify:      true,
	}

	err := client.renewTicket(config)
	assert.NoError(t, err)
}

func TestKrb5Client_RenewTicket_MissingCachePath(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{}
	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		RenewTicket: true,
	}

	err := client.renewTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cache path is required")
}

func TestKrb5Client_RenewTicket_InitContextError(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(0), fmt.Errorf("failed to init context")
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
	}

	err := client.renewTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize krb5 context")
}

func TestKrb5Client_RenewTicket_ResolveCacheError(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(0), fmt.Errorf("cache not found")
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
	}

	err := client.renewTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve cache")
}

func TestKrb5Client_RenewTicket_GetPrincipalError(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(200), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		getPrincipalFunc: func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
			return Krb5Principal(0), fmt.Errorf("failed to get principal")
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
	}

	err := client.renewTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get principal from cache")
}

func TestKrb5Client_RenewTicket_GetRenewedCredsError(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(200), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		getPrincipalFunc: func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
			return Krb5Principal(300), nil
		},
		freePrincipalFunc: func(ctx Krb5Context, princ Krb5Principal) {},
		getRenewedCredsFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
			return Krb5Creds(0), fmt.Errorf("renewal failed: ticket not renewable")
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
	}

	err := client.renewTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to renew ticket")
}

func TestKrb5Client_RenewTicket_InitializeCacheError(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(200), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		getPrincipalFunc: func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
			return Krb5Principal(300), nil
		},
		freePrincipalFunc: func(ctx Krb5Context, princ Krb5Principal) {},
		getRenewedCredsFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
			return Krb5Creds(400), nil
		},
		freeCredContentsFunc: func(ctx Krb5Context, creds Krb5Creds) {},
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
			return fmt.Errorf("failed to initialize cache")
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
	}

	err := client.renewTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to reinitialize cache")
}

func TestKrb5Client_RenewTicket_StoreCredError(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(200), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		getPrincipalFunc: func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
			return Krb5Principal(300), nil
		},
		freePrincipalFunc: func(ctx Krb5Context, princ Krb5Principal) {},
		getRenewedCredsFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
			return Krb5Creds(400), nil
		},
		freeCredContentsFunc: func(ctx Krb5Context, creds Krb5Creds) {},
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
			return nil
		},
		storeCredFunc: func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
			return fmt.Errorf("permission denied")
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
	}

	err := client.renewTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store renewed credentials")
}

func TestKrb5Client_RenewTicket_WithVerbose(t *testing.T) {
	// Capture stderr for verbose output
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(200), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		getPrincipalFunc: func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
			return Krb5Principal(300), nil
		},
		freePrincipalFunc: func(ctx Krb5Context, princ Krb5Principal) {},
		getRenewedCredsFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
			return Krb5Creds(400), nil
		},
		freeCredContentsFunc: func(ctx Krb5Context, creds Krb5Creds) {},
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
			return nil
		},
		storeCredFunc: func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
			return nil
		},
		runKlistFunc: func(ccachePath string) error {
			return nil
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
		Verbose:     true,
		Verify:      true,
	}

	err := client.renewTicket(config)
	assert.NoError(t, err)

	// Close writer and read output
	if err := w.Close(); err != nil {
		t.Logf("Failed to close writer: %v", err)
	}

	var buf [512]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	os.Stderr = oldStderr

	// Check verbose output
	assert.Contains(t, output, "Successfully renewed Kerberos ticket")
	assert.Contains(t, output, "/tmp/krb5cc_test")
}

func TestKrb5Client_RenewTicket_VerifyFailure(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(200), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		getPrincipalFunc: func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
			return Krb5Principal(300), nil
		},
		freePrincipalFunc: func(ctx Krb5Context, princ Krb5Principal) {},
		getRenewedCredsFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
			return Krb5Creds(400), nil
		},
		freeCredContentsFunc: func(ctx Krb5Context, creds Krb5Creds) {},
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
			return nil
		},
		storeCredFunc: func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
			return nil
		},
		runKlistFunc: func(ccachePath string) error {
			return fmt.Errorf("klist verification failed")
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
		Verify:      true,
	}

	err := client.renewTicket(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ticket verification failed")
}

func TestKrb5Client_RenewTicket_WithoutVerify(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(200), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		getPrincipalFunc: func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
			return Krb5Principal(300), nil
		},
		freePrincipalFunc: func(ctx Krb5Context, princ Krb5Principal) {},
		getRenewedCredsFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
			return Krb5Creds(400), nil
		},
		freeCredContentsFunc: func(ctx Krb5Context, creds Krb5Creds) {},
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
			return nil
		},
		storeCredFunc: func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
			return nil
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
		Verify:      false, // Skip verification
	}

	err := client.renewTicket(config)
	assert.NoError(t, err)
}

func TestKrb5Client_RenewTicket_WithoutVerbose(t *testing.T) {
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(200), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		getPrincipalFunc: func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
			return Krb5Principal(300), nil
		},
		freePrincipalFunc: func(ctx Krb5Context, princ Krb5Principal) {},
		getRenewedCredsFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
			return Krb5Creds(400), nil
		},
		freeCredContentsFunc: func(ctx Krb5Context, creds Krb5Creds) {},
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
			return nil
		},
		storeCredFunc: func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
			return nil
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
		Verbose:     false, // No verbose output
		Verify:      false,
	}

	err := client.renewTicket(config)
	assert.NoError(t, err)
}

func TestKrb5Client_GenerateTicket_RenewalPath(t *testing.T) {
	// Test that GenerateTicket correctly routes to renewTicket when RenewTicket is true
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(200), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		getPrincipalFunc: func(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
			return Krb5Principal(300), nil
		},
		freePrincipalFunc: func(ctx Krb5Context, princ Krb5Principal) {},
		getRenewedCredsFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
			return Krb5Creds(400), nil
		},
		freeCredContentsFunc: func(ctx Krb5Context, creds Krb5Creds) {},
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
			return nil
		},
		storeCredFunc: func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
			return nil
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: true,
	}

	// Call GenerateTicket, which should route to renewTicket
	err := client.GenerateTicket(config)
	assert.NoError(t, err)
}

func TestKrb5Client_GenerateTicket_InitialTicketPath(t *testing.T) {
	// Test that GenerateTicket correctly routes to generateInitialTicket when RenewTicket is false
	mockWrapper := &mockKrb5Wrapper{
		initContextFunc: func() (Krb5Context, error) {
			return Krb5Context(100), nil
		},
		freeContextFunc: func(ctx Krb5Context) {},
		parseNameFunc: func(ctx Krb5Context, principal string) (Krb5Principal, error) {
			return Krb5Principal(200), nil
		},
		freePrincipalFunc: func(ctx Krb5Context, princ Krb5Principal) {},
		allocCredOptionsFunc: func(ctx Krb5Context) (Krb5CredOptions, error) {
			return Krb5CredOptions(300), nil
		},
		freeCredOptionsFunc: func(ctx Krb5Context, opts Krb5CredOptions) {},
		setForwardableFunc:  func(opts Krb5CredOptions, value bool) {},
		setProxiableFunc:    func(opts Krb5CredOptions, value bool) {},
		getInitCredsPasswordFunc: func(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error) {
			return Krb5Creds(400), nil
		},
		freeCredContentsFunc: func(ctx Krb5Context, creds Krb5Creds) {},
		resolveCacheFunc: func(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
			return Krb5Ccache(500), nil
		},
		closeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache) {},
		initializeCacheFunc: func(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
			return nil
		},
		storeCredFunc: func(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
			return nil
		},
		mkdirAllFunc: func(path string, perm os.FileMode) error {
			return nil
		},
		chmodFunc: func(path string, mode os.FileMode) error {
			return nil
		},
		statFunc: func(path string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	client := &krb5Client{wrapper: mockWrapper}
	config := &KinitConfig{
		Principal:   "user@EXAMPLE.COM",
		Password:    "password",
		CCachePath:  "/tmp/krb5cc_test",
		RenewTicket: false, // Initial ticket, not renewal
	}

	// Call GenerateTicket, which should route to generateInitialTicket
	err := client.GenerateTicket(config)
	assert.NoError(t, err)
}
