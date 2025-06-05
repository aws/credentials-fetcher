package aws_utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test ParseS3ARN function
func TestParseS3ARN(t *testing.T) {
	tests := []struct {
		name        string
		s3ARN       string
		wantBucket  string
		wantKey     string
		wantErr     bool
		errContains string
	}{
		{
			name:       "Valid ARN",
			s3ARN:      "arn:aws:s3:::my-bucket/path/to/object.json",
			wantBucket: "my-bucket",
			wantKey:    "path/to/object.json",
			wantErr:    false,
		},
		{
			name:        "Invalid ARN format",
			s3ARN:       "invalid-arn",
			wantErr:     true,
			errContains: "invalid S3 ARN format",
		},
		{
			name:        "ARN without bucket",
			s3ARN:       "arn:aws:s3:::",
			wantErr:     true,
			errContains: "invalid S3 ARN format",
		},
		{
			name:        "ARN without key",
			s3ARN:       "arn:aws:s3:::my-bucket",
			wantErr:     true,
			errContains: "invalid S3 ARN format",
		},
		{
			name:       "ARN with partition",
			s3ARN:      "arn:aws-cn:s3:::my-bucket/object.json",
			wantBucket: "my-bucket",
			wantKey:    "object.json",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, key, err := ParseS3ARN(tt.s3ARN)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantBucket, bucket)
			assert.Equal(t, tt.wantKey, key)
		})
	}
}
