package main

import (
	"context"
	"io"
	"os"
	"os/exec"
)

// peakMemory runs this program again for one engine and reports the largest
// resident set of that run in MiB, children included. Every engine is
// measured in a process of its own, so one engine's memory never counts for
// another's. It returns 0 where the platform gives no figure.
func peakMemory(ctx context.Context, suite, repo, expected, engine string) (float64, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	args := []string{"--suite", suite, "--repo", repo, "--engine", engine, "--json"}
	if expected != "" {
		args = append(args, "--expected", expected)
	}
	cmd := exec.CommandContext(ctx, self, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return 0, err
	}
	return maxRSSMiB(cmd.ProcessState), nil
}
