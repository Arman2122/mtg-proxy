//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// setProcAttrs puts the child in its own process group, and has the kernel
// kill it if mtgbench dies -- even by SIGKILL, which no deferred Close survives.
func setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// terminate and kill signal the child through its os.Process, which since Go
// 1.23 holds a pidfd on Linux: a child that has exited and been reaped can
// never be confused with whoever got its id next. The binary starts no
// children of its own -- taskset replaces itself with it -- so the process is
// the whole tree.
func terminate(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM) //nolint: errcheck
	}
}

func kill(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}

	return cmd.Process.Kill() //nolint: wrapcheck
}

// clockTicks is USER_HZ, which Linux fixes at 100 for /proc on every
// architecture mtgbench runs on.
const clockTicks = 100

// cpuSeconds reads utime and stime, fields 14 and 15 of /proc/<pid>/stat. The
// second field, the command, is in parentheses and may hold spaces, so fields
// are counted after its closing parenthesis.
func cpuSeconds(pid int) (float64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, fmt.Errorf("cannot read the CPU time of %d: %w", pid, err)
	}

	fields := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:]))
	if len(fields) < 13 {
		return 0, fmt.Errorf("unexpected /proc/%d/stat", pid)
	}

	utime, err1 := strconv.ParseFloat(fields[11], 64)
	stime, err2 := strconv.ParseFloat(fields[12], 64)

	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("unexpected /proc/%d/stat times", pid)
	}

	return (utime + stime) / clockTicks, nil
}

// rssBytes reads VmRSS from /proc/<pid>/status.
func rssBytes(pid int) (int64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, fmt.Errorf("cannot read the memory of %d: %w", pid, err)
	}

	for line := range strings.SplitSeq(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			kb, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("unexpected VmRSS for %d: %w", pid, err)
			}

			return kb << 10, nil
		}
	}

	return 0, fmt.Errorf("no VmRSS for %d", pid)
}
