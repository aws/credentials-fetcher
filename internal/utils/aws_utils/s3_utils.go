package aws_utils

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

// For testing - allows us to mock the s3.NewFromConfig function
var s3NewFromConfig = func(cfg aws.Config) *s3.Client {
	return s3.NewFromConfig(cfg)
}

// CheckFileSizeS3 checks if the S3 object is valid
func CheckFileSizeS3(ctx context.Context, cfg aws.Config, s3ARN string) (bool, error) {
	log := logger.GetInstance()
	log.Info("Checking S3 object size", "arn", s3ARN)

	// Parse S3 ARN
	bucket, key, err := ParseS3ARN(s3ARN)
	if err != nil {
		return false, err
	}

	// Create S3 client
	s3Client := s3NewFromConfig(cfg)

	// Get object metadata
	headObj, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		log.Error("Failed to get S3 object metadata", "error", err)
		return false, fmt.Errorf("failed to get S3 object metadata: %w", err)
	}

	// Check if object size is valid (not empty and not too large)
	if *headObj.ContentLength == 0 || *headObj.ContentLength > 4000 { // Max 4KB
		log.Error("Invalid S3 object size", "size", *headObj.ContentLength)
		return false, nil
	}

	return true, nil
}

// RetrieveCredSpecFromS3 retrieves credential spec from S3
// Example ARN format: arn:aws:s3:::gmsacredspec/gmsa-cred-spec.json
func RetrieveCredSpecFromS3(ctx context.Context, cfg aws.Config, s3ARN string) (string, error) {
	log := logger.GetInstance()
	log.Info("Retrieving credential spec from S3", "arn", s3ARN)

	// Parse S3 ARN using regex
	bucket, key, err := ParseS3ARN(s3ARN)
	if err != nil {
		log.Error("Invalid S3 ARN format", "arn", s3ARN, "error", err)
		return "", err
	}

	// Create S3 client
	s3Client := s3NewFromConfig(cfg)

	// Get object
	getObj, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		log.Error("Failed to get S3 object", "bucket", bucket, "key", key, "error", err)
		return "", fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer func() {
		if err := getObj.Body.Close(); err != nil {
			log.Error("Failed to close S3 object body", "error", err)
		}
	}()

	// Read object content
	buf := new(strings.Builder)
	_, err = io.Copy(buf, getObj.Body)
	if err != nil {
		log.Error("Failed to read S3 object content", "error", err)
		return "", fmt.Errorf("failed to read S3 object content: %w", err)
	}

	log.Info("Successfully retrieved credential spec from S3")
	return buf.String(), nil
}

// ParseS3ARN parses an S3 ARN into bucket and key using regex
// Format: arn:aws:s3:::bucket-name/object-key
func ParseS3ARN(s3ARN string) (string, string, error) {
	// Use regex to parse the ARN
	re := regexp.MustCompile(`arn:([^:]+):s3:::([^/]+)/(.+)`)
	matches := re.FindStringSubmatch(s3ARN)

	if matches == nil || len(matches) != 4 {
		return "", "", fmt.Errorf("invalid S3 ARN format: %s", s3ARN)
	}

	bucket := matches[2]
	key := matches[3]

	return bucket, key, nil
}
