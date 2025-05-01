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
	BuildCommand(command string, args ...string) string
}

type DefaultExecutor struct{}

func NewExecutor() *DefaultExecutor {
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

// BuildCommand creates a string representation of the command to be executed
func (e *DefaultExecutor) BuildCommand(command string, args ...string) string {
	fullCommand := []string{command}
	fullCommand = append(fullCommand, args...)
	return strings.Join(fullCommand, " ")
}
