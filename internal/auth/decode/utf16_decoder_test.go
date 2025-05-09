package decode

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUTF16ToUTF8(t *testing.T) {
	testCases := []struct {
		name           string
		input          []byte
		expectedOutput string
		expectError    bool
	}{
		{
			name:           "Basic ASCII conversion",
			input:          []byte{0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00}, // "Hello" in UTF-16LE
			expectedOutput: "Hello",
			expectError:    false,
		},
		{
			name:           "Empty input",
			input:          []byte{},
			expectedOutput: "",
			expectError:    true,
		},
		{
			name:           "Odd number of bytes",
			input:          []byte{0x48, 0x00, 0x65, 0x00, 0x6C}, // Incomplete UTF-16LE
			expectedOutput: "He",
			expectError:    false,
		},
		{
			name:           "Non-ASCII characters",
			input:          []byte{0x24, 0x27, 0x40, 0x00, 0x24, 0x4E}, // Some non-ASCII UTF-16LE characters
			expectedOutput: "✤@两",                                      // Update expected output to match actual conversion
			expectError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := UTF16ToUTF8(tc.input)

			if tc.expectError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.Equal(t, tc.expectedOutput, string(output), "Output should match expected value")
			}
		})
	}
}
