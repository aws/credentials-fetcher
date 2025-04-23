package ldap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	client := NewClient(nil)
	assert.NotNil(t, client)
}

func TestGetBaseDN(t *testing.T) {
	client := NewClient(nil)
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "simple domain",
			domain:   "example.com",
			expected: "DC=example,DC=com",
		},
		{
			name:     "subdomain",
			domain:   "sub.example.com",
			expected: "DC=sub,DC=example,DC=com",
		},
		{
			name:     "multiple subdomains",
			domain:   "deep.sub.example.com",
			expected: "DC=deep,DC=sub,DC=example,DC=com",
		},
		{
			name:     "single label",
			domain:   "local",
			expected: "DC=local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.GetBaseDN(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindServiceAccountDN(t *testing.T) {

	client := NewClient(nil)
	ctx := context.Background()

	tests := []struct {
		name      string
		account   string
		baseDN    string
		fqdn      string
		expectErr bool
	}{
		{
			name:      "invalid account",
			account:   "nonexistent",
			baseDN:    "DC=example,DC=com",
			fqdn:      "ldap.example.com",
			expectErr: true,
		},
		{
			name:      "invalid base DN",
			account:   "valid",
			baseDN:    "DC=invalid,DC=com",
			fqdn:      "ldap.example.com",
			expectErr: true,
		},
		{
			name:      "invalid FQDN",
			account:   "valid",
			baseDN:    "DC=example,DC=com",
			fqdn:      "invalid.example.com",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dn, err := client.FindServiceAccountDN(ctx, tt.account, tt.baseDN, tt.fqdn)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Empty(t, dn)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, dn)
			}
		})
	}
}

func TestSearchGMSAPassword(t *testing.T) {
	client := NewClient(nil)
	ctx := context.Background()

	tests := []struct {
		name      string
		dn        string
		fqdn      string
		expectErr bool
	}{
		{
			name:      "invalid DN",
			dn:        "CN=invalid,DC=example,DC=com",
			fqdn:      "ldap.example.com",
			expectErr: true,
		},
		{
			name:      "invalid FQDN",
			dn:        "CN=valid,DC=example,DC=com",
			fqdn:      "invalid.example.com",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := client.SearchGMSAPassword(ctx, tt.dn, tt.fqdn)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, password)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, password)
			}
		})
	}
}

func TestExtractDistinguishedName(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		expected  string
		expectErr bool
	}{
		{
			name: "valid output",
			output: `version: 1
dn: CN=service,DC=example,DC=com
distinguishedName: CN=service,DC=example,DC=com
objectClass: top`,
			expected:  "CN=service,DC=example,DC=com",
			expectErr: false,
		},
		{
			name: "no DN",
			output: `version: 1
objectClass: top`,
			expected:  "",
			expectErr: true,
		},
		{
			name:      "empty output",
			output:    "",
			expected:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dn, err := extractDistinguishedName(tt.output)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Empty(t, dn)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, dn)
			}
		})
	}
}
