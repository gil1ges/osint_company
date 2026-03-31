package util

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

func RunCommand(ctx context.Context, name string, args ...string) (CommandResult, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		}
		return result, fmt.Errorf("%s %v: %w: %s", name, args, err, stderr.String())
	}

	return result, nil
}

func CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
