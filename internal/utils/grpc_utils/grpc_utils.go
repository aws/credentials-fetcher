package grpc_utils

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/aws_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/config"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// GenerateLeaseID generates a random lease ID
func GenerateLeaseID() (string, error) {
	// Create a string builder for better performance
	var leaseID strings.Builder

	// Use crypto/rand for better randomness
	b := make([]byte, constants.LeaseIDLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random lease ID: %v", err)
	}

	// Convert bytes to hex string
	for _, v := range b {
		hex := fmt.Sprintf("%02x", v)
		leaseID.WriteString(hex)
	}

	return leaseID.String(), nil
}

// ParseCredSpec parses a credential spec JSON string
func ParseCredSpec(credspecData string) (*types.CredentialSpec, error) {
	log := logger.GetInstance()

	if credspecData == "" {
		log.Error("Credential spec is empty")
		return nil, fmt.Errorf("credential spec is empty")
	}

	// Parse JSON
	root, err := parseJSON(credspecData)
	if err != nil {
		return nil, err
	}

	// Extract domain information
	domainName, _, err := extractDomainInfo(root)
	if err != nil {
		return nil, err
	}

	// Extract service account name
	serviceAccountName, err := extractServiceAccountName(root)
	if err != nil {
		return nil, err
	}

	// Validate domain and service account
	if err := validateCredSpecFields(domainName, serviceAccountName); err != nil {
		return nil, err
	}

	// Extract credential ARN
	credentialArn, err := extractCredentialArn(root)
	if err != nil {
		return nil, err
	}

	return &types.CredentialSpec{
		DomainName:         domainName,
		ServiceAccountName: serviceAccountName,
		CredentialArn:      credentialArn,
	}, nil
}

// parseJSON parses the credential spec JSON string into a map
func parseJSON(credspecData string) (map[string]interface{}, error) {
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(credspecData), &root); err != nil {
		logger.GetInstance().Error("Failed to parse credential spec JSON", "error", err)
		return nil, fmt.Errorf("failed to parse credential spec JSON: %v", err)
	}
	return root, nil
}

// extractDomainInfo extracts domain information from the credential spec
func extractDomainInfo(root map[string]interface{}) (domainName string, netbiosName string, err error) {
	log := logger.GetInstance()

	domainJoinConfig, ok := root["DomainJoinConfig"].(map[string]interface{})
	if !ok {
		log.Error("Missing or invalid DomainJoinConfig in credential spec")
		return "", "", fmt.Errorf("missing or invalid DomainJoinConfig in credential spec")
	}

	domainName, ok = domainJoinConfig["DnsName"].(string)
	if !ok || domainName == "" {
		log.Error("Missing or invalid DnsName in credential spec")
		return "", "", fmt.Errorf("missing or invalid DnsName in credential spec")
	}

	if netbios, ok := domainJoinConfig["NetbiosName"].(string); ok {
		netbiosName = netbios
	}

	return domainName, netbiosName, nil
}

// extractServiceAccountName extracts the first non-empty service account name
func extractServiceAccountName(root map[string]interface{}) (string, error) {
	log := logger.GetInstance()

	activeDirectoryConfig, ok := root["ActiveDirectoryConfig"].(map[string]interface{})
	if !ok {
		log.Error("Missing or invalid ActiveDirectoryConfig in credential spec")
		return "", fmt.Errorf("missing or invalid ActiveDirectoryConfig in credential spec")
	}

	groupManagedServiceAccounts, ok := activeDirectoryConfig["GroupManagedServiceAccounts"].([]interface{})
	if !ok {
		log.Error("Missing or invalid GroupManagedServiceAccounts in credential spec")
		return "", fmt.Errorf("missing or invalid GroupManagedServiceAccounts in credential spec")
	}

	if len(groupManagedServiceAccounts) == 0 {
		log.Error("No GroupManagedServiceAccounts found in credential spec")
		return "", fmt.Errorf("no GroupManagedServiceAccounts found in credential spec")
	}

	// Find first non-empty service account name
	for _, account := range groupManagedServiceAccounts {
		accountMap, ok := account.(map[string]interface{})
		if !ok {
			continue
		}

		if name, ok := accountMap["Name"].(string); ok && name != "" {
			return name, nil
		}
	}

	log.Error("No valid service account name found in credential spec")
	return "", fmt.Errorf("no valid service account name found in credential spec")
}

// validateCredSpecFields validates the domain and service account name
func validateCredSpecFields(domainName, serviceAccountName string) error {
	log := logger.GetInstance()

	if err := ValidateDomain(domainName); err != nil {
		log.Error("Invalid domain name in credential spec", "domain", domainName, "error", err)
		return fmt.Errorf("invalid domain name in credential spec: %v", err)
	}

	if err := ValidateAccountName(serviceAccountName); err != nil {
		log.Error("Service account name contains invalid characters", "service_account", serviceAccountName, "error", err)
		return fmt.Errorf("service account name contains invalid characters")
	}

	return nil
}

// extractCredentialArn extracts the credential ARN from the credential spec
func extractCredentialArn(root map[string]interface{}) (string, error) {
	log := logger.GetInstance()

	activeDirectoryConfig, ok := root["ActiveDirectoryConfig"].(map[string]interface{})
	if !ok {
		log.Error("Missing or invalid ActiveDirectoryConfig in credential spec")
		return "", fmt.Errorf("missing or invalid ActiveDirectoryConfig in credential spec")
	}

	hostAccountConfig, ok := activeDirectoryConfig["HostAccountConfig"].(map[string]interface{})
	if !ok {
		log.Error("Missing or invalid HostAccountConfig in credential spec")
		return "", fmt.Errorf("missing or invalid HostAccountConfig in credential spec")
	}

	pluginInput, ok := hostAccountConfig["PluginInput"].(map[string]interface{})
	if !ok {
		log.Error("Missing or invalid PluginInput in credential spec")
		return "", fmt.Errorf("missing or invalid PluginInput in credential spec")
	}

	credentialArn, ok := pluginInput["CredentialArn"].(string)
	if !ok {
		log.Error("Missing or invalid CredentialArn in credential spec")
		return "", fmt.Errorf("missing or invalid CredentialArn in credential spec")
	}

	return credentialArn, nil
}

// ValidateAccountName checks if an account name contains invalid characters
func ValidateAccountName(username string) error {
	log := logger.GetInstance()

	// Check if username is empty
	if username == "" {
		log.Error("Username is empty")
		return fmt.Errorf("username cannot be empty")
	}

	// Check for invalid characters
	for _, char := range username {
		if strings.ContainsRune(constants.InvalidUsernameChars, char) || char == ' ' {
			log.Error("Username contains invalid character",
				"username", username,
				"invalid_char", string(char))
			return fmt.Errorf("username contains invalid character: %s", string(char))
		}
	}

	return nil
}

// ValidateDomain checks if a domain is valid using regex pattern
func ValidateDomain(domain string) error {
	log := logger.GetInstance()

	// Check if domain is empty
	if domain == "" {
		log.Error("Domain is empty")
		return fmt.Errorf("domain cannot be empty")
	}

	// Validate domain using regex pattern
	matched, err := regexp.MatchString(constants.DomainRegexPattern, domain)
	if err != nil {
		log.Error("Error validating domain", "domain", domain, "error", err)
		return fmt.Errorf("error validating domain: %v", err)
	}

	if !matched || !strings.Contains(domain, ".") {
		log.Error("Invalid domain format", "domain", domain)
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	return nil
}

// ValidateCredentialLength checks if credentials exceed maximum allowed lengths
func ValidateCredentialLength(username, password, domain string) error {
	log := logger.GetInstance()

	if len(username) > constants.MaxUsernameLength {
		log.Error("Username exceeds maximum length",
			"length", len(username),
			"max_length", constants.MaxUsernameLength)
		return fmt.Errorf("username exceeds maximum length of %d characters", constants.MaxUsernameLength)
	}

	if len(password) > constants.MaxPasswordLength {
		log.Error("Password exceeds maximum length",
			"length", len(password),
			"max_length", constants.MaxPasswordLength)
		return fmt.Errorf("password exceeds maximum length of %d characters", constants.MaxPasswordLength)
	}

	if len(domain) > constants.MaxDomainLength {
		log.Error("Domain exceeds maximum length",
			"length", len(domain),
			"max_length", constants.MaxDomainLength)
		return fmt.Errorf("domain exceeds maximum length of %d characters", constants.MaxDomainLength)
	}

	return nil
}

// GetBaseDnFromSecret retrieves the distinguished name from a secret in AWS Secrets Manager.
// It first tries to get the "distinguishedName" field, and if that's empty, it tries
// "distinguishedNameOfgMSA". Returns the distinguished name and an error if any.
func GetBaseDnFromSecret(secretArn string) (string, error) {
	log := logger.GetInstance()

	// Get the secret from AWS Secrets Manager
	secretData, err := aws_utils.GetSecretFromSecretsManager(secretArn)
	if err != nil {
		log.Error("Failed to get secret from Secrets Manager", "error", err)
		return "", fmt.Errorf("failed to get secret from Secrets Manager: %v", err)
	}

	// First try to get "distinguishedName"
	var distinguishedName string
	if dn, ok := secretData["distinguishedName"]; ok {
		if dnStr, ok := dn.(string); ok {
			distinguishedName = dnStr
		}
	}

	// If distinguishedName is empty, try "distinguishedNameOfgMSA"
	if distinguishedName == "" {
		if dn, ok := secretData["distinguishedNameOfgMSA"]; ok {
			if dnStr, ok := dn.(string); ok {
				distinguishedName = dnStr
			}
		}
	}

	return distinguishedName, nil
}

// GetBaseDnFromDomain converts a domain name (e.g., "contoso.com") to a base DN format (e.g., "DC=contoso,DC=com")
// Returns the base DN string and an error if the operation fails
func GetBaseDnFromDomain(domainName string) (string, error) {
	if domainName == "" {
		return "", fmt.Errorf("domain name cannot be empty")
	}

	// Split domain name by dots
	parts := strings.Split(domainName, ".")

	// Build the base DN string
	var baseDn strings.Builder
	for i, part := range parts {
		baseDn.WriteString("DC=" + part)
		if i < len(parts)-1 {
			baseDn.WriteString(",")
		}
	}

	return baseDn.String(), nil
}

// GetFQDNList retrieves a list of fully qualified domain names (FQDNs) for domain controllers
// It first checks for a domain controller specified in the environment variable,
// and if not found, it looks up domain controllers via DNS
func GetFQDNList(domainName string) ([]string, error) {
	log := logger.GetInstance()

	// Check for domain controller in environment variable
	domainControllerEnvVar := "CF_DOMAIN_CONTROLLER"
	fqdnFromEnvVar, err := config.RetrieveVariableFromECSConfig(domainControllerEnvVar)
	if err != nil {
		log.Warn("Failed to retrieve domain controller from ECS config", "error", err)
		// Continue with DNS lookup even if there's an error reading the config
	}

	var fqdnList []string
	if fqdnFromEnvVar == "" {
		// If environment variable is not set, look up domain controllers via DNS
		var err error
		fqdnList, err = getFQDNs(domainName)
		if err != nil {
			log.Error("Failed to get FQDNs for domain", "domain", domainName, "error", err)
			return nil, fmt.Errorf("failed to get FQDNs for domain %s: %v", domainName, err)
		}

		// Log found domain controllers
		for _, fqdn := range fqdnList {
			log.Info("Found ldap._tcp.dc._msdcs DNS controller", "fqdn", fqdn)
		}
	} else {
		// Use the domain controller from environment variable
		fqdnList = append(fqdnList, fqdnFromEnvVar)
	}

	return fqdnList, nil
}

// getFQDNs retrieves a list of fully qualified domain names (FQDNs) for domain controllers
// using DNS SRV records. It first tries using nslookup, and if that fails, it tries using dig.
func getFQDNs(domainName string) ([]string, error) {
	log := logger.GetInstance()
	ctx := context.Background()
	executor := cmdexec.NewExecutor()

	// First try using nslookup with parameters passed as separate arguments
	srvRecord := fmt.Sprintf("_ldap._tcp.dc._msdcs.%s", domainName)
	output, err := executor.Execute(ctx, "nslookup", "-type=srv", srvRecord)

	if err == nil && len(output) > 0 {
		// Filter lines containing the domain name
		var filteredOutput strings.Builder
		lines := strings.Split(string(output), "\n")

		for _, line := range lines {
			if strings.Contains(line, domainName) {
				filteredOutput.WriteString(line)
				filteredOutput.WriteString("\n")
			}
		}

		// Extract FQDNs from the filtered output
		fqdns := parseFQDNsFromOutput(filteredOutput.String())
		if len(fqdns) > 0 {
			return fqdns, nil
		}
	}

	// If nslookup failed or returned no results, try using dig
	log.Debug("nslookup failed or returned no results, trying dig", "domain", domainName)
	output, err = executor.Execute(ctx, "dig", "+short", srvRecord, "-t", "any")

	if err == nil && len(output) > 0 {
		// Extract FQDNs from the dig output
		fqdns := parseFQDNsFromOutput(string(output))
		if len(fqdns) > 0 {
			return fqdns, nil
		}
	} else if err != nil {
		log.Error("Failed to execute dig command", "error", err)
		return nil, fmt.Errorf("failed to execute DNS lookup commands: %v", err)
	}

	// If we got here, both commands failed or returned no results
	log.Warn("No domain controllers found via DNS lookup", "domain", domainName)
	return []string{}, nil
}

// parseFQDNsFromOutput parses the output of nslookup or dig commands to extract FQDNs
func parseFQDNsFromOutput(output string) []string {
	// Split the output by newlines
	lines := strings.Split(output, "\n")

	// Extract FQDNs from each line
	var fqdns []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Extract the last field from the line
		fields := strings.Fields(line)
		if len(fields) > 0 {
			fqdn := fields[len(fields)-1]

			// Remove trailing dot if present
			if strings.HasSuffix(fqdn, ".") {
				fqdn = fqdn[:len(fqdn)-1]
			}

			fqdns = append(fqdns, fqdn)
		}
	}

	return fqdns
}
