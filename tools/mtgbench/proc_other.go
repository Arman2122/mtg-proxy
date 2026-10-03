//go:build !linux

package main

import (
	"errors"
	"os/exec"
)

// errNoProc: CPU time and resident memory come from /proc, so off Linux they
// are reported as unavailable rather than guessed.
var errNoProc = errors.New("CPU and memory readings need Linux /proc")

func setProcAttrs(*exec.Cmd) {}

func terminate(cmd *exec.Cmd) {
	kill(cmd) //nolint: errcheck // no gentler signal reaches a Windows process
}

func kill(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}

	return cmd.Process.Kill() //nolint: wrapcheck
}

func cpuSeconds(int) (float64, error) { return 0, errNoProc }
func rssBytes(int) (int64, error)     { return 0, errNoProc }
