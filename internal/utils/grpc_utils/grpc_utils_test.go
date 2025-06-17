package grpc_utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.a2z.com/CredentialsFetcherV2/constants"
)

func TestGenerateLeaseID(t *testing.T) {
	// Test generating multiple lease IDs to ensure they're unique and properly formatted
	leaseID1, err := GenerateLeaseID()
	require.NoError(t, err)
	assert.Len(t, leaseID1, constants.LeaseIDLength*2) // Each byte becomes 2 hex chars

	leaseID2, err := GenerateLeaseID()
	require.NoError(t, err)
	assert.Len(t, leaseID2, constants.LeaseIDLength*2)

	// Ensure they're different
	assert.NotEqual(t, leaseID1, leaseID2)

	// Ensure they contain only hex characters
	hexChars := "0123456789abcdef"
	for _, c := range leaseID1 {
		assert.Contains(t, hexChars, string(c))
	}
}

func TestParseCredSpec(t *testing.T) {
	// Valid credential spec
	validCredSpec := `{
		"DomainJoinConfig": {
			"DnsName": "example.com",
			"NetbiosName": "EXAMPLE"
		},
		"ActiveDirectoryConfig": {
			"GroupManagedServiceAccounts": [
				{
					"Name": "WebApp01",
					"Scope": "example.com"
				}
			],
			"HostAccountConfig": {
				"PluginInput": {
					"CredentialArn": "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret"
				}
			}
		}
	}`

	t.Run("Valid CredSpec", func(t *testing.T) {
		credSpec, err := ParseCredSpec(validCredSpec)
		require.NoError(t, err)
		assert.Equal(t, "example.com", credSpec.DomainName)
		assert.Equal(t, "WebApp01", credSpec.ServiceAccountName)
		assert.Equal(t, "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret", credSpec.CredentialArn)
	})

	t.Run("Empty CredSpec", func(t *testing.T) {
		_, err := ParseCredSpec("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "credential spec is empty")
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		_, err := ParseCredSpec("{invalid json}")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse credential spec JSON")
	})

	t.Run("Missing DomainJoinConfig", func(t *testing.T) {
		badCredSpec := `{
			"ActiveDirectoryConfig": {
				"GroupManagedServiceAccounts": [
					{
						"Name": "WebApp01",
						"Scope": "example.com"
					}
				]
			}
		}`
		_, err := ParseCredSpec(badCredSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid DomainJoinConfig")
	})

	t.Run("Missing DnsName", func(t *testing.T) {
		badCredSpec := `{
			"DomainJoinConfig": {
				"NetbiosName": "EXAMPLE"
			},
			"ActiveDirectoryConfig": {
				"GroupManagedServiceAccounts": [
					{
						"Name": "WebApp01",
						"Scope": "example.com"
					}
				]
			}
		}`
		_, err := ParseCredSpec(badCredSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid DnsName")
	})

	t.Run("Missing ActiveDirectoryConfig", func(t *testing.T) {
		badCredSpec := `{
			"DomainJoinConfig": {
				"DnsName": "example.com",
				"NetbiosName": "EXAMPLE"
			}
		}`
		_, err := ParseCredSpec(badCredSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid ActiveDirectoryConfig")
	})

	t.Run("Missing GroupManagedServiceAccounts", func(t *testing.T) {
		badCredSpec := `{
			"DomainJoinConfig": {
				"DnsName": "example.com",
				"NetbiosName": "EXAMPLE"
			},
			"ActiveDirectoryConfig": {}
		}`
		_, err := ParseCredSpec(badCredSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid GroupManagedServiceAccounts")
	})

	t.Run("Empty GroupManagedServiceAccounts", func(t *testing.T) {
		badCredSpec := `{
			"DomainJoinConfig": {
				"DnsName": "example.com",
				"NetbiosName": "EXAMPLE"
			},
			"ActiveDirectoryConfig": {
				"GroupManagedServiceAccounts": []
			}
		}`
		_, err := ParseCredSpec(badCredSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no GroupManagedServiceAccounts found")
	})

	t.Run("No Valid Service Account Name", func(t *testing.T) {
		badCredSpec := `{
			"DomainJoinConfig": {
				"DnsName": "example.com",
				"NetbiosName": "EXAMPLE"
			},
			"ActiveDirectoryConfig": {
				"GroupManagedServiceAccounts": [
					{
						"Scope": "example.com"
					}
				]
			}
		}`
		_, err := ParseCredSpec(badCredSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no valid service account name found")
	})

	t.Run("Invalid Domain Name", func(t *testing.T) {
		badCredSpec := `{
			"DomainJoinConfig": {
				"DnsName": "invalid_domain",
				"NetbiosName": "EXAMPLE"
			},
			"ActiveDirectoryConfig": {
				"GroupManagedServiceAccounts": [
					{
						"Name": "WebApp01",
						"Scope": "example.com"
					}
				]
			}
		}`
		_, err := ParseCredSpec(badCredSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid domain format")
	})

	t.Run("Invalid Service Account Name", func(t *testing.T) {
		badCredSpec := `{
			"DomainJoinConfig": {
				"DnsName": "example.com",
				"NetbiosName": "EXAMPLE"
			},
			"ActiveDirectoryConfig": {
				"GroupManagedServiceAccounts": [
					{
						"Name": "Web App/01",
						"Scope": "example.com"
					}
				]
			}
		}`
		_, err := ParseCredSpec(badCredSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "service account name contains invalid characters")
	})

	t.Run("Domain Joined Host (No HostAccountConfig)", func(t *testing.T) {
		domainJoinedCredSpec := `{
			"DomainJoinConfig": {
				"DnsName": "example.com",
				"NetbiosName": "EXAMPLE"
			},
			"ActiveDirectoryConfig": {
				"GroupManagedServiceAccounts": [
					{
						"Name": "WebApp01",
						"Scope": "example.com"
					}
				]
			}
		}`
		credSpec, err := ParseCredSpec(domainJoinedCredSpec)
		require.NoError(t, err)
		assert.Equal(t, "example.com", credSpec.DomainName)
		assert.Equal(t, "WebApp01", credSpec.ServiceAccountName)
		assert.Equal(t, "", credSpec.CredentialArn) // Empty credential ARN for domain-joined host
	})

	t.Run("Missing PluginInput", func(t *testing.T) {
		badCredSpec := `{
			"DomainJoinConfig": {
				"DnsName": "example.com",
				"NetbiosName": "EXAMPLE"
			},
			"ActiveDirectoryConfig": {
				"GroupManagedServiceAccounts": [
					{
						"Name": "WebApp01",
						"Scope": "example.com"
					}
				],
				"HostAccountConfig": {}
			}
		}`
		_, err := ParseCredSpec(badCredSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid PluginInput")
	})

	t.Run("Missing CredentialArn", func(t *testing.T) {
		badCredSpec := `{
			"DomainJoinConfig": {
				"DnsName": "example.com",
				"NetbiosName": "EXAMPLE"
			},
			"ActiveDirectoryConfig": {
				"GroupManagedServiceAccounts": [
					{
						"Name": "WebApp01",
						"Scope": "example.com"
					}
				],
				"HostAccountConfig": {
					"PluginInput": {}
				}
			}
		}`
		_, err := ParseCredSpec(badCredSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid CredentialArn")
	})
}

func TestValidateAccountName(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{
			name:     "Valid username",
			username: "validuser",
			wantErr:  false,
		},
		{
			name:     "Empty username",
			username: "",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character &",
			username: "invalid&user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character :",
			username: "invalid:user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character ]",
			username: "invalid]user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character [",
			username: "invalid[user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character +",
			username: "invalid+user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character |",
			username: "invalid|user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character ;",
			username: "invalid;user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character $",
			username: "invalid$user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character *",
			username: "invalid*user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character ?",
			username: "invalid?user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character <",
			username: "invalid<user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character >",
			username: "invalid>user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character !",
			username: "invalid!user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character space",
			username: "invalid user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character /",
			username: "invalid/user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character \\",
			username: "invalid\\user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character '",
			username: "invalid'user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character `",
			username: "invalid`user",
			wantErr:  true,
		},
		{
			name:     "Username with invalid character ~",
			username: "invalid~user",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAccountName(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAccountName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{
			name:    "Valid domain",
			domain:  "example.com",
			wantErr: false,
		},
		{
			name:    "Valid domain with subdomain",
			domain:  "sub.example.com",
			wantErr: false,
		},
		{
			name:    "Valid domain with hyphen",
			domain:  "example-domain.com",
			wantErr: false,
		},
		{
			name:    "Empty domain",
			domain:  "",
			wantErr: true,
		},
		{
			name:    "Invalid domain - no dot",
			domain:  "examplecom",
			wantErr: true,
		},
		{
			name:    "Invalid domain - starts with dot",
			domain:  ".example.com",
			wantErr: true,
		},
		{
			name:    "Invalid domain - ends with dot",
			domain:  "example.com.",
			wantErr: true,
		},
		{
			name:    "Invalid domain - starts with hyphen",
			domain:  "-example.com",
			wantErr: true,
		},
		{
			name:    "Invalid domain - part ends with hyphen",
			domain:  "example-.com",
			wantErr: true,
		},
		{
			name:    "Invalid domain - contains invalid character",
			domain:  "example_domain.com",
			wantErr: true,
		},
		{
			name:    "Invalid domain - contains space",
			domain:  "example domain.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomain() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCredentialLength(t *testing.T) {
	// Create strings of exact maximum lengths
	maxLengthUsername := strings.Repeat("a", constants.MaxUsernameLength)
	maxLengthPassword := strings.Repeat("b", constants.MaxPasswordLength)
	maxLengthDomain := strings.Repeat("c", constants.MaxDomainLength)

	// Create strings exceeding maximum lengths
	tooLongUsername := strings.Repeat("a", constants.MaxUsernameLength+1)
	tooLongPassword := strings.Repeat("b", constants.MaxPasswordLength+1)
	tooLongDomain := strings.Repeat("c", constants.MaxDomainLength+1)

	tests := []struct {
		name     string
		username string
		password string
		domain   string
		wantErr  bool
	}{
		{
			name:     "All credentials within limits",
			username: "validuser",
			password: "validpass",
			domain:   "example.com",
			wantErr:  false,
		},
		{
			name:     "All credentials at maximum length",
			username: maxLengthUsername,
			password: maxLengthPassword,
			domain:   maxLengthDomain,
			wantErr:  false,
		},
		{
			name:     "Username too long",
			username: tooLongUsername,
			password: "validpass",
			domain:   "example.com",
			wantErr:  true,
		},
		{
			name:     "Password too long",
			username: "validuser",
			password: tooLongPassword,
			domain:   "example.com",
			wantErr:  true,
		},
		{
			name:     "Domain too long",
			username: "validuser",
			password: "validpass",
			domain:   tooLongDomain,
			wantErr:  true,
		},
		{
			name:     "All credentials too long",
			username: tooLongUsername,
			password: tooLongPassword,
			domain:   tooLongDomain,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCredentialLength(tt.username, tt.password, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCredentialLength() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetBaseDnFromDomain(t *testing.T) {
	tests := []struct {
		name       string
		domainName string
		want       string
		wantErr    bool
	}{
		{
			name:       "Simple domain",
			domainName: "example.com",
			want:       "DC=example,DC=com",
			wantErr:    false,
		},
		{
			name:       "Domain with subdomain",
			domainName: "sub.example.com",
			want:       "DC=sub,DC=example,DC=com",
			wantErr:    false,
		},
		{
			name:       "Empty domain",
			domainName: "",
			want:       "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetBaseDnFromDomain(tt.domainName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetBaseDnFromDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetBaseDnFromDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseFQDNsFromOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   []string
	}{
		{
			name: "nslookup output",
			output: `Server:  192.168.1.1
Address:  192.168.1.1#53

_ldap._tcp.dc._msdcs.example.com  service = 0 100 389 dc1.example.com
_ldap._tcp.dc._msdcs.example.com  service = 0 100 389 dc2.example.com`,
			want: []string{"dc1.example.com", "dc2.example.com", "192.168.1.1", "192.168.1.1#53"},
		},
		{
			name: "dig output",
			output: `0 100 389 dc1.example.com.
0 100 389 dc2.example.com.`,
			want: []string{"dc1.example.com", "dc2.example.com"},
		},
		{
			name:   "empty output",
			output: "",
			want:   []string{},
		},
		{
			name:   "output without FQDNs",
			output: "No servers could be reached.",
			want:   []string{"reached"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFQDNsFromOutput(tt.output)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestSecureClearString(t *testing.T) {
	// Test with a non-empty string
	sensitiveData := "sensitive-password"
	SecureClearString(&sensitiveData)
	assert.Equal(t, "", sensitiveData, "String should be empty after secure clearing")

	// Test with an empty string
	emptyString := ""
	SecureClearString(&emptyString)
	assert.Equal(t, "", emptyString, "Empty string should remain empty after secure clearing")

	// Test with a nil pointer (should not panic)
	assert.NotPanics(t, func() {
		SecureClearString(nil)
	}, "SecureClearString should not panic with nil input")
}
