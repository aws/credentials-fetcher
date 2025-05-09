package decode

import (
	"fmt"
	"unicode/utf16"

	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

var log = logger.GetInstance()

// UTF16ToUTF8 converts UTF-16 encoded bytes to UTF-8 encoded bytes
// This uses Go's built-in UTF-16 decoding functionality
func UTF16ToUTF8(utf16Bytes []byte) ([]byte, error) {
	log.Debug("Converting UTF-16 to UTF-8", "input_size", len(utf16Bytes))

	// Check if we have valid input
	if len(utf16Bytes) == 0 {
		return nil, fmt.Errorf("empty UTF-16 input")
	}

	// Ensure we have an even number of bytes (UTF-16 uses 2 bytes per character)
	if len(utf16Bytes)%2 != 0 {
		log.Warn("UTF-16 input has odd number of bytes, truncating last byte",
			"input_size", len(utf16Bytes))
		utf16Bytes = utf16Bytes[:len(utf16Bytes)-1]
	}

	// Convert byte array to uint16 array (UTF-16 code units)
	utf16Units := make([]uint16, len(utf16Bytes)/2)
	for i := 0; i < len(utf16Units); i++ {
		// Little endian: least significant byte first
		utf16Units[i] = uint16(utf16Bytes[i*2]) | (uint16(utf16Bytes[i*2+1]) << 8)
	}

	// Decode UTF-16 to UTF-8 using Go's built-in functionality
	// This handles surrogate pairs correctly
	s := string(utf16.Decode(utf16Units))

	// The result is already in UTF-8 format
	result := []byte(s)

	log.Debug("UTF-16 to UTF-8 conversion completed",
		"input_size", len(utf16Bytes),
		"output_size", len(result))

	return result, nil
}
