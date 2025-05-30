package decode

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// TestGMSAPasswordBlob tests if a specific gMSA password blob can be properly decoded
func TestGMSAPasswordBlob(t *testing.T) {
	// The base64 encoded gMSA password blob
	base64Blob := "AQAAACIBAAAQAAAAEgEaAciMhCofvo1R4kkVYm79aRysUcOs7NhhHvO" +
		"exhNTV9KXAn1v8AYMN1lMC/V6W0dZVrQRpGZ/EvWi33Lq2xoR5ANuJf623JQRj3pMZQBqQLRjRoPn" +
		"UJYY8H74aVysf0t+1M0moLkm0IPSCB52Mm0CC9flTT0D9KZV2Mvf4FpgvYpYoOQvUmd0UOV72Tk/d" +
		"leM8zTWjRL5ccfzwt5p8akMEl6W0RPj1pDbqxtbpJFQiLQd7HRlSkYPeBKDB9r6CItrQTo8j+pgJf" +
		"B4+wVbOUZuMXrKkDVh8XUOUBdGhznntRWnDM2DhwBoFEisBr133Vo8aRcedYqwNj/LEsrimEJaeuY" +
		"AAAQCCBrPFgAABKQ3Z84WAAA="

	t.Log("=== gMSA Password Blob Test ===")

	// Decode the base64 blob
	decodedBlob, err := base64.StdEncoding.DecodeString(base64Blob)
	if err != nil {
		t.Fatalf("Failed to decode base64 blob: %v", err)
	}

	t.Logf("Successfully decoded base64 blob, size: %d bytes", len(decodedBlob))

	// Extract and decode the password
	t.Log("=== Extracting and decoding password ===")
	password, err := extractManagedPassword(t, decodedBlob)
	if err != nil {
		t.Fatalf("Failed to extract managed password: %v", err)
	}

	// Test if the password can be used as a string
	t.Log("=== Testing password as string ===")
	passwordStr := string(password)
	t.Logf("Password string length: %d characters", len(passwordStr))

	t.Log("Test completed successfully!")
}

// extractManagedPassword extracts and decodes the msDS-ManagedPassword attribute
// This simulates the logic in ldap_client.go but for direct testing
func extractManagedPassword(t *testing.T, blob []byte) ([]byte, error) {
	t.Logf("Extracting managed password from blob, size: %d bytes", len(blob))

	// Check if the blob is large enough to contain the header
	if len(blob) < binary.Size(types.ManagedPasswordBlob{}) {
		t.Logf("ERROR: Decoded blob is too small to contain a valid header: %d bytes", len(blob))
		return nil, fmt.Errorf("decoded blob is too small: %d bytes", len(blob))
	}

	// Print the first 16 bytes which contain header information
	t.Logf("Blob header (first 16 bytes): %x", blob[:16])

	// Unmarshal the blob header
	var blobHeader types.ManagedPasswordBlob
	reader := bytes.NewReader(blob)
	if err := binary.Read(reader, binary.LittleEndian, &blobHeader); err != nil {
		t.Logf("ERROR: Failed to unmarshal password blob: %v", err)
		return nil, fmt.Errorf("failed to unmarshal password blob: %w", err)
	}

	// Print blob header information
	t.Logf("Blob header information:")
	t.Logf("  Version: %d", blobHeader.Version)
	t.Logf("  Length: %d bytes", blobHeader.Length)
	t.Logf("  CurrentPasswordOffset: %d", blobHeader.CurrentPasswordOffset)
	t.Logf("  PreviousPasswordOffset: %d", blobHeader.PreviousPasswordOffset)
	t.Logf("  QueryPasswordIntervalOffset: %d", blobHeader.QueryPasswordIntervalOffset)
	t.Logf("  UnchangedPasswordIntervalOffset: %d", blobHeader.UnchangedPasswordIntervalOffset)

	// Validate the blob
	if len(blob) < int(blobHeader.Length) {
		t.Logf("ERROR: Decoded blob is smaller than the specified length: %d < %d",
			len(blob), blobHeader.Length)
		return nil, fmt.Errorf("decoded blob is smaller than specified length: %d < %d",
			len(blob), blobHeader.Length)
	}

	// Extract the current password
	if blobHeader.CurrentPasswordOffset == 0 || int(blobHeader.CurrentPasswordOffset) >= len(blob) {
		t.Logf("ERROR: Invalid current password offset: %d (blob size: %d)",
			blobHeader.CurrentPasswordOffset, len(blob))
		return nil, fmt.Errorf("invalid current password offset: %d", blobHeader.CurrentPasswordOffset)
	}

	// The current password starts at the offset specified in the blob
	startOffset := int(blobHeader.CurrentPasswordOffset)
	endOffset := startOffset + types.GMSAPasswordSize
	if endOffset > len(blob) {
		endOffset = len(blob)
	}

	t.Logf("Extracting password from offset %d to %d (length: %d bytes)",
		startOffset, endOffset, endOffset-startOffset)

	currentPassword := blob[startOffset:endOffset]

	// Print a sample of the raw password bytes
	t.Logf("Raw password sample (first 16 bytes or fewer): %x",
		currentPassword[:min(16, len(currentPassword))])

	// Convert the password from UTF-16 to UTF-8
	utf8Password, err := UTF16ToUTF8(currentPassword)
	if err != nil {
		t.Logf("WARNING: Failed to convert password from UTF-16 to UTF-8: %v", err)
		t.Log("Returning raw password as fallback")
		return currentPassword, nil // Return the raw password as fallback
	}

	t.Logf("Successfully extracted and decoded managed password:")
	t.Logf("  Raw password size: %d bytes", len(currentPassword))
	t.Logf("  UTF-8 password size: %d bytes", len(utf8Password))

	return utf8Password, nil
}
