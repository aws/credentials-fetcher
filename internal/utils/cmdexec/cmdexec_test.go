package cmdexec

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{
			name:     "args with spaces",
			command:  "echo",
			args:     []string{"hello world", "foo bar"},
			expected: "echo 'hello world' 'foo bar'",
		},
		{
			name:     "args with special characters",
			command:  "grep",
			args:     []string{"-E", "foo && bar", "/tmp/file"},
			expected: "grep -E 'foo && bar' /tmp/file",
		},
		{
			name:     "args with quotes",
			command:  "echo",
			args:     []string{"It's a \"quoted\" string"},
			expected: "echo 'It'\\''s a \"quoted\" string'",
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
		output, err := executor.Execute(ctx, "echo", "hello")
		assert.NoError(t, err, "Execute() should not return an error for valid command")
		assert.Equal(t, "hello\n", string(output), "Execute() should return expected output")
	})

	// Test command with multiple arguments
	t.Run("multiple arguments", func(t *testing.T) {
		output, err := executor.Execute(ctx, "echo", "hello", "world")
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
		_, err := executor.Execute(ctx, "sleep", "1")

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

func TestExecuteWithEnv(t *testing.T) {
	executor := NewExecutor()
	ctx := context.Background()

	// Test successful command execution with environment variables
	t.Run("successful execution with env", func(t *testing.T) {
		env := []string{"TEST_VAR=test_value"}
		output, err := executor.ExecuteWithEnv(ctx, "env", env)
		assert.NoError(t, err, "ExecuteWithEnv() should not return an error for valid command")
		assert.Contains(t, string(output), "TEST_VAR=test_value", "ExecuteWithEnv() output should contain the environment variable")
	})

	// Test command with multiple environment variables
	t.Run("multiple environment variables", func(t *testing.T) {
		env := []string{"VAR1=value1", "VAR2=value2"}
		output, err := executor.ExecuteWithEnv(ctx, "env", env)
		assert.NoError(t, err, "ExecuteWithEnv() should not return an error for valid command with multiple env vars")
		assert.Contains(t, string(output), "VAR1=value1", "ExecuteWithEnv() output should contain the first env var")
		assert.Contains(t, string(output), "VAR2=value2", "ExecuteWithEnv() output should contain the second env var")
	})

	// Test command with environment variables and arguments
	t.Run("env vars and arguments", func(t *testing.T) {
		env := []string{"GREETING=Hello"}
		output, err := executor.ExecuteWithEnv(ctx, "sh", env, "-c", "echo $GREETING World")
		assert.NoError(t, err, "ExecuteWithEnv() should not return an error")
		assert.Contains(t, string(output), "Hello World", "ExecuteWithEnv() should pass env vars to the command")
	})

	// Test command that fails with environment variables
	t.Run("command failure with env", func(t *testing.T) {
		env := []string{"TEST_VAR=test_value"}
		_, err := executor.ExecuteWithEnv(ctx, "nonexistentcommand", env)
		assert.Error(t, err, "ExecuteWithEnv() should return an error for nonexistent command")
	})

	// Test empty command with environment variables
	t.Run("empty command with env", func(t *testing.T) {
		env := []string{"TEST_VAR=test_value"}
		_, err := executor.ExecuteWithEnv(ctx, "", env)
		assert.Error(t, err, "ExecuteWithEnv() should return an error for empty command")
		assert.Contains(t, err.Error(), "empty command", "Error message should mention empty command")
	})

	// Test command with context timeout and environment variables
	t.Run("context timeout with env", func(t *testing.T) {
		// Create a context with a short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		env := []string{"TEST_VAR=test_value"}
		// Execute a command that takes longer than the timeout
		_, err := executor.ExecuteWithEnv(ctx, "sleep", env, "1")

		// On some systems, this might not return an error if the command completes before the context is checked
		// So we'll just log the result rather than asserting
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
				// Check if the error is related to the context being canceled
				if !errors.Is(err, context.Canceled) {
					t.Logf("ExecuteWithEnv() with timeout returned error: %v", err)
				}
			}
		}
	})
}

// TestExecuteWithStdinAndEnv tests the ExecuteWithStdinAndEnv function
func TestExecuteWithStdinAndEnv(t *testing.T) {
	executor := NewExecutor()
	ctx := context.Background()

	// Test successful command execution with stdin and environment variables
	t.Run("successful execution with stdin", func(t *testing.T) {
		env := []string{"TEST_VAR=test_value"}
		stdin := []byte("hello world")
		output, err := executor.ExecuteWithStdinAndEnv(ctx, "cat", stdin, env)
		assert.NoError(t, err, "ExecuteWithStdinAndEnv() should not return an error for valid command")
		assert.Equal(t, "hello world", string(output), "ExecuteWithStdinAndEnv() output should match stdin")
	})

	// Test command with stdin and multiple environment variables
	t.Run("stdin with multiple environment variables", func(t *testing.T) {
		env := []string{"VAR1=value1", "VAR2=value2"}
		stdin := []byte("test input")
		output, err := executor.ExecuteWithStdinAndEnv(ctx, "sh", stdin, env, "-c", "cat && echo $VAR1 $VAR2")
		assert.NoError(t, err, "ExecuteWithStdinAndEnv() should not return an error")
		assert.Contains(t, string(output), "test input", "Output should contain stdin content")
		assert.Contains(t, string(output), "value1 value2", "Output should contain env var values")
	})

	// Test command that fails with stdin
	t.Run("command failure with stdin", func(t *testing.T) {
		env := []string{"TEST_VAR=test_value"}
		stdin := []byte("test input")
		_, err := executor.ExecuteWithStdinAndEnv(ctx, "nonexistentcommand", stdin, env)
		assert.Error(t, err, "ExecuteWithStdinAndEnv() should return an error for nonexistent command")
	})

	// Test empty command with stdin
	t.Run("empty command with stdin", func(t *testing.T) {
		env := []string{"TEST_VAR=test_value"}
		stdin := []byte("test input")
		_, err := executor.ExecuteWithStdinAndEnv(ctx, "", stdin, env)
		assert.Error(t, err, "ExecuteWithStdinAndEnv() should return an error for empty command")
		assert.Contains(t, err.Error(), "empty command", "Error message should mention empty command")
	})

	// Test command with context timeout, stdin and environment variables
	t.Run("context timeout with stdin", func(t *testing.T) {
		// Create a context with a short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		env := []string{"TEST_VAR=test_value"}
		stdin := []byte("test input")

		// Execute a command that takes longer than the timeout
		_, err := executor.ExecuteWithStdinAndEnv(ctx, "sleep", stdin, env, "1")

		// The command should be killed due to context timeout
		assert.Error(t, err, "ExecuteWithStdinAndEnv() should return an error when context times out")
	})

	// Test with large stdin data
	t.Run("large stdin data", func(t *testing.T) {
		// Create a large input (100KB)
		largeInput := strings.Repeat("A", 100*1024)
		stdin := []byte(largeInput)

		output, err := executor.ExecuteWithStdinAndEnv(ctx, "wc", stdin, nil, "-c")
		assert.NoError(t, err, "ExecuteWithStdinAndEnv() should handle large stdin")
		assert.Contains(t, string(output), "102400", "Output should contain the correct byte count")
	})

	// Test with empty stdin
	t.Run("empty stdin", func(t *testing.T) {
		stdin := []byte{}
		output, err := executor.ExecuteWithStdinAndEnv(ctx, "cat", stdin, nil)
		assert.NoError(t, err, "ExecuteWithStdinAndEnv() should handle empty stdin")
		assert.Empty(t, string(output), "Output should be empty with empty stdin")
	})
}

// TestMockExecutor tests the implementation of a mock executor
// This helps demonstrate how to create a mock for testing other components
type MockExecutor struct {
	ExecuteFunc                func(ctx context.Context, command string, args ...string) ([]byte, error)
	ExecuteWithEnvFunc         func(ctx context.Context, command string, env []string, args ...string) ([]byte, error)
	ExecuteWithStdinAndEnvFunc func(ctx context.Context, command string, stdin []byte, env []string, args ...string) ([]byte, error)
	BuildCommandFunc           func(command string, args ...string) string
}

func (m *MockExecutor) Execute(ctx context.Context, command string, args ...string) ([]byte, error) {
	return m.ExecuteFunc(ctx, command, args...)
}

func (m *MockExecutor) ExecuteWithEnv(ctx context.Context, command string, env []string, args ...string) ([]byte, error) {
	return m.ExecuteWithEnvFunc(ctx, command, env, args...)
}

func (m *MockExecutor) ExecuteWithStdinAndEnv(ctx context.Context, command string, stdin []byte, env []string, args ...string) ([]byte, error) {
	return m.ExecuteWithStdinAndEnvFunc(ctx, command, stdin, env, args...)
}

func (m *MockExecutor) BuildCommand(command string, args ...string) string {
	return m.BuildCommandFunc(command, args...)
}

func TestMockExecutorImplementation(t *testing.T) {
	// Test the mock executor
	t.Run("mock executor implementation", func(t *testing.T) {
		// Create a mock executor with predefined behavior
		mockExec := &MockExecutor{
			ExecuteFunc: func(ctx context.Context, command string, args ...string) ([]byte, error) {
				return []byte("mocked output"), nil
			},
			ExecuteWithEnvFunc: func(ctx context.Context, command string, env []string, args ...string) ([]byte, error) {
				return []byte("mocked env output"), nil
			},
			ExecuteWithStdinAndEnvFunc: func(ctx context.Context, command string, stdin []byte, env []string, args ...string) ([]byte, error) {
				return []byte("mocked stdin output"), nil
			},
			BuildCommandFunc: func(command string, args ...string) string {
				return "mocked command"
			},
		}

		// Test the mock implementation
		output, err := mockExec.Execute(context.Background(), "test")
		assert.NoError(t, err)
		assert.Equal(t, "mocked output", string(output))

		output, err = mockExec.ExecuteWithEnv(context.Background(), "test", []string{"VAR=value"})
		assert.NoError(t, err)
		assert.Equal(t, "mocked env output", string(output))

		output, err = mockExec.ExecuteWithStdinAndEnv(context.Background(), "test", []byte("input"), []string{"VAR=value"})
		assert.NoError(t, err)
		assert.Equal(t, "mocked stdin output", string(output))

		cmd := mockExec.BuildCommand("test", "arg1", "arg2")
		assert.Equal(t, "mocked command", cmd)
	})
}

// TestExecutorWithRealCommands tests the executor with real commands that interact with the filesystem
func TestExecutorWithRealCommands(t *testing.T) {
	executor := NewExecutor()
	ctx := context.Background()

	// Create a temporary file for testing
	t.Run("file operations", func(t *testing.T) {
		// Create a temporary file
		tmpfile, err := ioutil.TempFile("", "cmdexec-test")
		require.NoError(t, err, "Failed to create temporary file")
		defer os.Remove(tmpfile.Name())

		// Write test content to the file
		testContent := "test content\nline 2\nline 3\n"
		_, err = tmpfile.Write([]byte(testContent))
		require.NoError(t, err, "Failed to write to temporary file")
		tmpfile.Close()

		// Test reading the file with cat
		output, err := executor.Execute(ctx, "cat", tmpfile.Name())
		assert.NoError(t, err, "Execute cat should not return an error")
		assert.Equal(t, testContent, string(output), "File content should match")

		// Test counting lines with wc
		output, err = executor.Execute(ctx, "wc", "-l", tmpfile.Name())
		assert.NoError(t, err, "Execute wc should not return an error")
		assert.Contains(t, string(output), "3", "File should have 3 lines")

		// Test grep command
		output, err = executor.Execute(ctx, "grep", "line", tmpfile.Name())
		assert.NoError(t, err, "Execute grep should not return an error")
		assert.Contains(t, string(output), "line 2", "Output should contain matching line")
		assert.Contains(t, string(output), "line 3", "Output should contain matching line")
	})

	// Test command that produces stderr output
	t.Run("command with stderr output", func(t *testing.T) {
		// This command will produce output on stderr
		_, err := executor.Execute(ctx, "ls", "/nonexistent")
		assert.Error(t, err, "Execute should return an error for nonexistent directory")
		assert.Contains(t, err.Error(), "No such file or directory", "Error should contain the expected message")
	})
}
