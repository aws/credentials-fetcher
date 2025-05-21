package cmdexec

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

var log = logger.GetInstance()

type Executor interface {
	Execute(ctx context.Context, command string, args ...string) ([]byte, error)
	ExecuteWithEnv(ctx context.Context, command string, env []string, args ...string) ([]byte, error)
	ExecuteWithStdin(ctx context.Context, command string, stdin []byte, args ...string) ([]byte, error)
	ExecuteWithStdinAndEnv(ctx context.Context, command string, stdin []byte, env []string, args ...string) ([]byte, error)
	BuildCommand(command string, args ...string) string
}

type DefaultExecutor struct{}

func NewExecutor() Executor {
	return &DefaultExecutor{}
}

// Execute runs a shell command with separate command and arguments to prevent command injection
func (e *DefaultExecutor) Execute(ctx context.Context, command string, args ...string) ([]byte, error) {
	if command == "" {
		return nil, fmt.Errorf("empty command")
	}

	cmd := exec.CommandContext(ctx, command, args...)

	commandString := e.BuildCommand(command, args...)
	log.Debug("Executing shell command",
		"command", commandString)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Shell command failed",
			"error", err,
			"output", string(output),
			"command", commandString)
		return nil, fmt.Errorf("command execution failed: %w: %s", err, string(output))
	}

	log.Debug("Shell command completed successfully",
		"output_size", len(output),
		"command", commandString)

	return output, nil
}

// ExecuteWithEnv runs a shell command with the specified environment variables and returns its output
// This version accepts command and arguments separately to prevent command injection
func (e *DefaultExecutor) ExecuteWithEnv(ctx context.Context, command string, env []string, args ...string) ([]byte, error) {
	if command == "" {
		return nil, fmt.Errorf("empty command")
	}

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = append(cmd.Environ(), env...)

	commandString := e.BuildCommand(command, args...)
	log.Debug("Executing shell command with environment variables",
		"command", commandString,
		"env", env)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Shell command with environment variables failed",
			"error", err,
			"output", string(output),
			"command", commandString,
			"env", env)
		return nil, fmt.Errorf("command execution with environment variables failed: %w: %s", err, string(output))
	}

	log.Debug("Shell command with environment variables completed successfully",
		"output_size", len(output),
		"command", commandString)

	return output, nil
}

// BuildCommand creates a string representation of the command to be executed
func (e *DefaultExecutor) BuildCommand(command string, args ...string) string {
	// Quote arguments that contain spaces or special characters
	quotedArgs := make([]string, len(args))
	for i, arg := range args {
		if strings.ContainsAny(arg, " \t\n\r\"'$&|;<>(){}[]") {
			quotedArgs[i] = fmt.Sprintf("'%s'", strings.Replace(arg, "'", "'\\''", -1))
		} else {
			quotedArgs[i] = arg
		}
	}

	fullCommand := []string{command}
	fullCommand = append(fullCommand, quotedArgs...)
	return strings.Join(fullCommand, " ")
}

// ExecuteWithStdinAndEnv runs a shell command with the specified environment variables and stdin input
// This allows piping data to the command's standard input
func (e *DefaultExecutor) ExecuteWithStdinAndEnv(ctx context.Context, command string, stdin []byte, env []string, args ...string) ([]byte, error) {
	if command == "" {
		return nil, fmt.Errorf("empty command")
	}

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = append(cmd.Environ(), env...)

	// Create stdin pipe
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	// Create buffer for output
	var outputBuf strings.Builder
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf

	commandString := e.BuildCommand(command, args...)
	log.Debug("Executing shell command with environment variables and stdin",
		"command", commandString,
		"env", env)

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("command start failed: %w", err)
	}

	// Write to stdin and close it
	_, err = stdinPipe.Write(stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to write to stdin: %w", err)
	}
	err = stdinPipe.Close()
	if err != nil {
		return nil, err
	}

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		output := outputBuf.String()
		log.Error("Shell command with environment variables and stdin failed",
			"error", err,
			"output", output,
			"command", commandString,
			"env", env)
		return []byte(output), fmt.Errorf("command execution failed: %w: %s", err, output)
	}

	output := outputBuf.String()
	log.Debug("Shell command with environment variables and stdin completed successfully",
		"output_size", len(output),
		"command", commandString)

	return []byte(output), nil
}

// ExecuteWithStdin runs a shell command with stdin input but without custom environment variables
// This allows piping data to the command's standard input
func (e *DefaultExecutor) ExecuteWithStdin(ctx context.Context, command string, stdin []byte, args ...string) ([]byte, error) {
	if command == "" {
		return nil, fmt.Errorf("empty command")
	}

	cmd := exec.CommandContext(ctx, command, args...)

	// Create stdin pipe
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	// Create buffer for output
	var outputBuf strings.Builder
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf

	commandString := e.BuildCommand(command, args...)
	log.Debug("Executing shell command with stdin",
		"command", commandString)

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("command start failed: %w", err)
	}

	// Write to stdin and close it
	_, err = stdinPipe.Write(stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to write to stdin: %w", err)
	}
	err = stdinPipe.Close()
	if err != nil {
		return nil, err
	}

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		output := outputBuf.String()
		log.Error("Shell command with stdin failed",
			"error", err,
			"output", output,
			"command", commandString)
		return []byte(output), fmt.Errorf("command execution failed: %w: %s", err, output)
	}

	output := outputBuf.String()
	log.Debug("Shell command with stdin completed successfully",
		"output_size", len(output),
		"command", commandString)

	return []byte(output), nil
}
