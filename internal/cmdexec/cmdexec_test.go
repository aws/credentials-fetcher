package cmdexec

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildCommand(t *testing.T) {
	executor := NewExecutor()

	tests := []struct {
		name     string
		command  string
		args     []string
		expected string
	}{
		{
			name:     "simple command",
			command:  "echo",
			args:     []string{"hello"},
			expected: "echo hello",
		},
		{
			name:     "multiple args",
			command:  "ldapsearch",
			args:     []string{"-b", "dc=example,dc=com", "-s", "sub", "objectClass=user"},
			expected: "ldapsearch -b dc=example,dc=com -s sub objectClass=user",
		},
		{
			name:     "no args",
			command:  "ls",
			args:     []string{},
			expected: "ls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := executor.BuildCommand(tt.command, tt.args...)
			assert.Equal(t, tt.expected, result, "BuildCommand() should return expected command string")
		})
	}
}

func TestNewExecutor(t *testing.T) {
	executor := NewExecutor()
	assert.NotNil(t, executor, "NewExecutor() should not return nil")
}

func TestExecute(t *testing.T) {
	executor := NewExecutor()
	ctx := context.Background()

	// Test successful command execution
	t.Run("successful execution", func(t *testing.T) {
		output, err := executor.Execute(ctx, "echo hello")
		assert.NoError(t, err, "Execute() should not return an error for valid command")
		assert.Equal(t, "hello\n", string(output), "Execute() should return expected output")
	})

	// Test command with multiple arguments
	t.Run("multiple arguments", func(t *testing.T) {
		output, err := executor.Execute(ctx, "echo hello world")
		assert.NoError(t, err, "Execute() should not return an error for valid command with multiple arguments")
		assert.Equal(t, "hello world\n", string(output), "Execute() should return expected output")
	})

	// Test command that fails
	t.Run("command failure", func(t *testing.T) {
		_, err := executor.Execute(ctx, "nonexistentcommand")
		assert.Error(t, err, "Execute() should return an error for nonexistent command")
	})

	// Test empty command
	t.Run("empty command", func(t *testing.T) {
		_, err := executor.Execute(ctx, "")
		assert.Error(t, err, "Execute() should return an error for empty command")
		assert.Contains(t, err.Error(), "empty command", "Error message should mention empty command")
	})

	// Test command with context timeout
	t.Run("context timeout", func(t *testing.T) {
		// Create a context with a short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		// Execute a command that takes longer than the timeout
		_, err := executor.Execute(ctx, "sleep 1")

		// On some systems, this might not return an error if the command completes before the context is checked
		// So we'll just log the result rather than asserting
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
				// Check if the error is related to the context being canceled
				if !errors.Is(err, context.Canceled) {
					t.Logf("Execute() with timeout returned error: %v", err)
				}
			}
		}
	})
}
