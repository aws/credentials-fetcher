package cgo

/*
#cgo LDFLAGS: -lkrb5
#include <krb5.h>
#include <stdlib.h>
#include <string.h>

// Helper function to get error message
char* get_krb5_error_message(krb5_context ctx, krb5_error_code code) {
    return (char*)krb5_get_error_message(ctx, code);
}

void free_error_message(krb5_context ctx, char* msg) {
    krb5_free_error_message(ctx, msg);
}
*/
import "C"
import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unsafe"
)

// Opaque types for C structures
type (
	Krb5Context     interface{}
	Krb5Principal   interface{}
	Krb5Ccache      interface{}
	Krb5Creds       interface{}
	Krb5CredOptions interface{}
)

// Krb5Wrapper is a low-level interface that wraps individual krb5 C library calls
// This allows for comprehensive mocking and testing of all krb5 operations
type Krb5Wrapper interface {
	// Context management
	InitContext() (Krb5Context, error)
	FreeContext(ctx Krb5Context)

	// Principal operations
	ParseName(ctx Krb5Context, principal string) (Krb5Principal, error)
	FreePrincipal(ctx Krb5Context, princ Krb5Principal)

	// Credential options
	AllocCredOptions(ctx Krb5Context) (Krb5CredOptions, error)
	FreeCredOptions(ctx Krb5Context, opts Krb5CredOptions)
	SetForwardable(opts Krb5CredOptions, value bool)
	SetProxiable(opts Krb5CredOptions, value bool)
	SetTicketLifetime(opts Krb5CredOptions, lifetime int32)
	SetRenewableLife(opts Krb5CredOptions, lifetime int32)

	// Renewal operations
	GetRenewedCreds(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error)

	// Credential operations
	GetInitCredsPassword(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error)
	FreeCredContents(ctx Krb5Context, creds Krb5Creds)

	// Cache operations
	ResolveCache(ctx Krb5Context, cachePath string) (Krb5Ccache, error)
	DefaultCache(ctx Krb5Context) (Krb5Ccache, error)
	GetCacheName(ctx Krb5Context, cache Krb5Ccache) string
	CloseCache(ctx Krb5Context, cache Krb5Ccache)
	InitializeCache(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error
	GetPrincipal(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error)
	StoreCred(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error

	// Error handling
	GetErrorMessage(ctx Krb5Context, code int) string

	// File system operations
	MkdirAll(path string, perm os.FileMode) error
	Chmod(path string, mode os.FileMode) error
	Stat(path string) (os.FileInfo, error)

	// Utility operations
	RunKlist(ccachePath string) error
}

// cgoKrb5Wrapper implements Krb5Wrapper using CGO to call MIT Kerberos C libraries
type cgoKrb5Wrapper struct{}

// NewCGOWrapper creates a new CGO-based Krb5Wrapper
func NewCGOWrapper() Krb5Wrapper {
	return &cgoKrb5Wrapper{}
}

// InitContext initializes a krb5 context
func (w *cgoKrb5Wrapper) InitContext() (Krb5Context, error) {
	var context C.krb5_context
	ret := C.krb5_init_context(&context)
	if ret != 0 {
		return nil, fmt.Errorf("failed to initialize krb5 context (error code %d)", ret)
	}
	return context, nil
}

// FreeContext frees a krb5 context
func (w *cgoKrb5Wrapper) FreeContext(ctx Krb5Context) {
	if ctx != nil {
		C.krb5_free_context(ctx.(C.krb5_context))
	}
}

// ParseName parses a principal name string
func (w *cgoKrb5Wrapper) ParseName(ctx Krb5Context, principal string) (Krb5Principal, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	context := ctx.(C.krb5_context)
	var princ C.krb5_principal

	cPrincipal := C.CString(principal)
	defer C.free(unsafe.Pointer(cPrincipal))

	ret := C.krb5_parse_name(context, cPrincipal, &princ)
	if ret != 0 {
		return nil, fmt.Errorf("failed to parse principal '%s': %s", principal, w.GetErrorMessage(ctx, int(ret)))
	}

	return princ, nil
}

// FreePrincipal frees a principal
func (w *cgoKrb5Wrapper) FreePrincipal(ctx Krb5Context, princ Krb5Principal) {
	if ctx != nil && princ != nil {
		C.krb5_free_principal(ctx.(C.krb5_context), princ.(C.krb5_principal))
	}
}

// AllocCredOptions allocates credential options
func (w *cgoKrb5Wrapper) AllocCredOptions(ctx Krb5Context) (Krb5CredOptions, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	context := ctx.(C.krb5_context)
	var opts *C.krb5_get_init_creds_opt

	ret := C.krb5_get_init_creds_opt_alloc(context, &opts)
	if ret != 0 {
		return nil, fmt.Errorf("failed to allocate options: %s", w.GetErrorMessage(ctx, int(ret)))
	}

	return opts, nil
}

// FreeCredOptions frees credential options
func (w *cgoKrb5Wrapper) FreeCredOptions(ctx Krb5Context, opts Krb5CredOptions) {
	if ctx != nil && opts != nil {
		C.krb5_get_init_creds_opt_free(ctx.(C.krb5_context), opts.(*C.krb5_get_init_creds_opt))
	}
}

// SetForwardable sets the forwardable flag on credential options
func (w *cgoKrb5Wrapper) SetForwardable(opts Krb5CredOptions, value bool) {
	if opts != nil {
		if value {
			C.krb5_get_init_creds_opt_set_forwardable(opts.(*C.krb5_get_init_creds_opt), 1)
		} else {
			C.krb5_get_init_creds_opt_set_forwardable(opts.(*C.krb5_get_init_creds_opt), 0)
		}
	}
}

// SetProxiable sets the proxiable flag on credential options
func (w *cgoKrb5Wrapper) SetProxiable(opts Krb5CredOptions, value bool) {
	if opts != nil {
		if value {
			C.krb5_get_init_creds_opt_set_proxiable(opts.(*C.krb5_get_init_creds_opt), 1)
		} else {
			C.krb5_get_init_creds_opt_set_proxiable(opts.(*C.krb5_get_init_creds_opt), 0)
		}
	}
}

// SetTicketLifetime sets the ticket lifetime on credential options
func (w *cgoKrb5Wrapper) SetTicketLifetime(opts Krb5CredOptions, lifetime int32) {
	if opts != nil && lifetime > 0 {
		C.krb5_get_init_creds_opt_set_tkt_life(opts.(*C.krb5_get_init_creds_opt), C.krb5_deltat(lifetime))
	}
}

// SetRenewableLife sets the renewable lifetime on credential options
func (w *cgoKrb5Wrapper) SetRenewableLife(opts Krb5CredOptions, lifetime int32) {
	if opts != nil && lifetime > 0 {
		C.krb5_get_init_creds_opt_set_renew_life(opts.(*C.krb5_get_init_creds_opt), C.krb5_deltat(lifetime))
	}
}

// GetInitCredsPassword gets initial credentials using a password
func (w *cgoKrb5Wrapper) GetInitCredsPassword(ctx Krb5Context, princ Krb5Principal, password string, opts Krb5CredOptions) (Krb5Creds, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	if princ == nil {
		return nil, fmt.Errorf("principal is nil")
	}
	context := ctx.(C.krb5_context)
	principal := princ.(C.krb5_principal)
	options := opts.(*C.krb5_get_init_creds_opt)

	var creds C.krb5_creds
	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	ret := C.krb5_get_init_creds_password(context, &creds, principal,
		cPassword, nil, nil, 0, nil, options)
	if ret != 0 {
		return nil, fmt.Errorf("authentication failed: %s", w.GetErrorMessage(ctx, int(ret)))
	}

	return &creds, nil
}

// GetRenewedCreds renews credentials from the credential cache
func (w *cgoKrb5Wrapper) GetRenewedCreds(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) (Krb5Creds, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	if cache == nil {
		return nil, fmt.Errorf("cache is nil")
	}
	if princ == nil {
		return nil, fmt.Errorf("principal is nil")
	}
	context := ctx.(C.krb5_context)
	ccache := cache.(C.krb5_ccache)
	principal := princ.(C.krb5_principal)

	var creds C.krb5_creds

	// Use krb5_get_renewed_creds to renew the ticket
	ret := C.krb5_get_renewed_creds(context, &creds, principal, ccache, nil)
	if ret != 0 {
		return nil, fmt.Errorf("renewal failed: %s", w.GetErrorMessage(ctx, int(ret)))
	}

	return &creds, nil
}

// GetPrincipal retrieves the principal from a credential cache
func (w *cgoKrb5Wrapper) GetPrincipal(ctx Krb5Context, cache Krb5Ccache) (Krb5Principal, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	if cache == nil {
		return nil, fmt.Errorf("cache is nil")
	}
	context := ctx.(C.krb5_context)
	ccache := cache.(C.krb5_ccache)

	var princ C.krb5_principal
	ret := C.krb5_cc_get_principal(context, ccache, &princ)
	if ret != 0 {
		return nil, fmt.Errorf("failed to get principal from cache: %s", w.GetErrorMessage(ctx, int(ret)))
	}

	return princ, nil
}

// FreeCredContents frees credential contents
func (w *cgoKrb5Wrapper) FreeCredContents(ctx Krb5Context, creds Krb5Creds) {
	if ctx != nil && creds != nil {
		C.krb5_free_cred_contents(ctx.(C.krb5_context), creds.(*C.krb5_creds))
	}
}

// ResolveCache resolves a credential cache by path
func (w *cgoKrb5Wrapper) ResolveCache(ctx Krb5Context, cachePath string) (Krb5Ccache, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	context := ctx.(C.krb5_context)
	var ccache C.krb5_ccache

	cCachePath := C.CString(fmt.Sprintf("FILE:%s", cachePath))
	defer C.free(unsafe.Pointer(cCachePath))

	ret := C.krb5_cc_resolve(context, cCachePath, &ccache)
	if ret != 0 {
		return nil, fmt.Errorf("failed to resolve ccache '%s': %s", cachePath, w.GetErrorMessage(ctx, int(ret)))
	}

	return ccache, nil
}

// DefaultCache gets the default credential cache
func (w *cgoKrb5Wrapper) DefaultCache(ctx Krb5Context) (Krb5Ccache, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	context := ctx.(C.krb5_context)
	var ccache C.krb5_ccache

	ret := C.krb5_cc_default(context, &ccache)
	if ret != 0 {
		return nil, fmt.Errorf("failed to get default ccache: %s", w.GetErrorMessage(ctx, int(ret)))
	}

	return ccache, nil
}

// GetCacheName gets the name of a credential cache
func (w *cgoKrb5Wrapper) GetCacheName(ctx Krb5Context, cache Krb5Ccache) string {
	if ctx == nil || cache == nil {
		return ""
	}

	context := ctx.(C.krb5_context)
	ccache := cache.(C.krb5_ccache)

	ccname := C.krb5_cc_get_name(context, ccache)
	if ccname != nil {
		return C.GoString(ccname)
	}

	return ""
}

// CloseCache closes a credential cache
func (w *cgoKrb5Wrapper) CloseCache(ctx Krb5Context, cache Krb5Ccache) {
	if ctx != nil && cache != nil {
		C.krb5_cc_close(ctx.(C.krb5_context), cache.(C.krb5_ccache))
	}
}

// InitializeCache initializes a credential cache with a principal
func (w *cgoKrb5Wrapper) InitializeCache(ctx Krb5Context, cache Krb5Ccache, princ Krb5Principal) error {
	if ctx == nil {
		return fmt.Errorf("context is nil")
	}
	if cache == nil {
		return fmt.Errorf("cache is nil")
	}
	if princ == nil {
		return fmt.Errorf("principal is nil")
	}
	context := ctx.(C.krb5_context)
	ccache := cache.(C.krb5_ccache)
	principal := princ.(C.krb5_principal)

	ret := C.krb5_cc_initialize(context, ccache, principal)
	if ret != 0 {
		return fmt.Errorf("failed to initialize ccache: %s", w.GetErrorMessage(ctx, int(ret)))
	}

	return nil
}

// StoreCred stores credentials in a credential cache
func (w *cgoKrb5Wrapper) StoreCred(ctx Krb5Context, cache Krb5Ccache, creds Krb5Creds) error {
	if ctx == nil {
		return fmt.Errorf("context is nil")
	}
	if cache == nil {
		return fmt.Errorf("cache is nil")
	}
	if creds == nil {
		return fmt.Errorf("credentials are nil")
	}
	context := ctx.(C.krb5_context)
	ccache := cache.(C.krb5_ccache)
	credentials := creds.(*C.krb5_creds)

	ret := C.krb5_cc_store_cred(context, ccache, credentials)
	if ret != 0 {
		return fmt.Errorf("failed to store credentials: %s", w.GetErrorMessage(ctx, int(ret)))
	}

	return nil
}

// GetErrorMessage retrieves a human-readable error message from krb5 error code
func (w *cgoKrb5Wrapper) GetErrorMessage(ctx Krb5Context, code int) string {
	if ctx == nil {
		return fmt.Sprintf("error code %d", code)
	}

	context := ctx.(C.krb5_context)
	msg := C.get_krb5_error_message(context, C.krb5_error_code(code))
	if msg == nil {
		return fmt.Sprintf("error code %d", code)
	}
	defer C.free_error_message(context, msg)
	return C.GoString(msg)
}

// RunKlist runs the klist command to verify a ticket
func (w *cgoKrb5Wrapper) RunKlist(ccachePath string) error {
	args := []string{}
	if ccachePath != "" {
		cleanPath := strings.TrimPrefix(ccachePath, "FILE:")
		args = append(args, "-c", cleanPath)
	}

	cmd := exec.Command("klist", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("klist failed: %w", err)
	}

	return nil
}

// MkdirAll creates a directory path with permissions
func (w *cgoKrb5Wrapper) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// Chmod changes file permissions
func (w *cgoKrb5Wrapper) Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

// Stat returns file information
func (w *cgoKrb5Wrapper) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
