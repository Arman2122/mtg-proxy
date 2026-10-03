package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcSpec is one child process. With Pin set, Core pins it to that CPU with
// taskset on Linux.
type ProcSpec struct {
	Name string
	Path string
	Args []string
	Env  []string
	Pin  bool
	Core int
}

// inheritedEnv are the only variables a child takes from mtgbench's own
// environment. The binary reads its configuration from the environment as
// well -- MTG_BIND_TO rebinds it, SECRET turns on a lookup that dials the
// internet directly, TAG starts the ad-tag path -- so nothing else passes.
var inheritedEnv = []string{"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "USERPROFILE", "LANG", "LC_ALL"}

func childEnv(extra []string) []string {
	env := make([]string, 0, len(inheritedEnv)+len(extra))

	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")

		for _, allowed := range inheritedEnv {
			if strings.EqualFold(key, allowed) {
				env = append(env, kv)

				break
			}
		}
	}

	return append(env, extra...)
}

type proc struct {
	spec   ProcSpec
	cmd    *exec.Cmd
	log    string
	exited chan struct{}
	err    error
}

// Runner owns the processes of one run. Whatever it starts, it stops: Close,
// a cancelled context and -- on Linux -- the death of mtgbench itself all end
// every child.
type Runner struct {
	procs []*proc
	once  sync.Once
}

var (
	errNotReady    = errors.New("not ready")
	errExitedEarly = errors.New("exited before it was ready")
)

// StartRunner starts the binary's proxy, and its WEB relay when web is set,
// both pinned to core.
func StartRunner(ctx context.Context, dir, bin, cfg string, core int, web bool) (*Runner, error) {
	pin := core != noPin

	specs := []ProcSpec{{Name: "proxy", Path: bin, Args: []string{"run", cfg}, Pin: pin, Core: core}}
	if web {
		specs = append(specs, ProcSpec{Name: "relay", Path: bin, Args: []string{"web-relay", cfg}, Pin: pin, Core: core})
	}

	return StartProcesses(ctx, dir, specs...)
}

// StartProcesses starts every spec, with its output in dir/<name>.log.
func StartProcesses(ctx context.Context, dir string, specs ...ProcSpec) (*Runner, error) {
	r := &Runner{}

	for _, spec := range specs {
		p, err := startProc(ctx, dir, spec)
		if err != nil {
			r.Close() //nolint: errcheck

			return nil, err
		}

		r.procs = append(r.procs, p)
	}

	return r, nil
}

func startProc(ctx context.Context, dir string, spec ProcSpec) (*proc, error) {
	path, args := spec.Path, spec.Args
	if spec.Pin && runtime.GOOS == "linux" {
		args = append([]string{"-c", strconv.Itoa(spec.Core), path}, args...)
		path = "taskset"
	}

	logPath := filepath.Join(dir, spec.Name+".log")

	logFile, err := os.Create(logPath) //nolint: gosec // a path mtgbench chose
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", logPath, err)
	}

	cmd := exec.CommandContext(ctx, path, args...) //nolint: gosec // the binary under test, by flag
	cmd.Env = childEnv(spec.Env)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// A cancelled run (SIGINT included) asks politely; WaitDelay kills a child
	// that has not gone five seconds later.
	cmd.Cancel = func() error {
		terminate(cmd)

		return nil
	}
	cmd.WaitDelay = 5 * time.Second
	setProcAttrs(cmd)

	if err := cmd.Start(); err != nil {
		logFile.Close() //nolint: errcheck

		return nil, fmt.Errorf("cannot start %s: %w", spec.Name, err)
	}

	p := &proc{spec: spec, cmd: cmd, log: logPath, exited: make(chan struct{})}

	go func() {
		p.err = cmd.Wait()
		logFile.Close() //nolint: errcheck
		close(p.exited)
	}()

	return p, nil
}

// noPin is a Core value meaning "do not pin", for callers that build specs
// from a flag.
const noPin = -1

// Close stops every child: a polite signal first, then a kill after three
// seconds. It waits for them, and is safe to call more than once.
func (r *Runner) Close() error {
	r.once.Do(func() {
		// Only children still running are signalled: a process that has exited
		// and been reaped may have had its id reused by someone else's.
		for _, p := range r.procs {
			select {
			case <-p.exited:
			default:
				terminate(p.cmd)
			}
		}

		for _, p := range r.procs {
			select {
			case <-p.exited:
			case <-time.After(3 * time.Second):
				kill(p.cmd) //nolint: errcheck
				<-p.exited
			}
		}
	})

	return nil
}

// WaitReady waits until every address accepts a connection. A child that has
// exited fails it at once, with the tail of its log.
func (r *Runner) WaitReady(ctx context.Context, addrs []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		for _, p := range r.procs {
			select {
			case <-p.exited:
				if p.err == nil {
					return fmt.Errorf("%s %w: %s", p.spec.Name, errExitedEarly, tail(p.log, 2048))
				}

				return fmt.Errorf("%s %w: %w: %s", p.spec.Name, errExitedEarly, p.err, tail(p.log, 2048))
			default:
			}
		}

		ready := true

		for _, addr := range addrs {
			conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "tcp", addr)
			if err != nil {
				ready = false

				break
			}

			conn.Close() //nolint: errcheck
		}

		if ready {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("%v after %s: %w", addrs, timeout, errNotReady)
		}

		select {
		case <-ctx.Done():
			return ctx.Err() //nolint: wrapcheck
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// PIDs are the children's process ids, for the /proc readings.
func (r *Runner) PIDs() []int {
	pids := make([]int, 0, len(r.procs))
	for _, p := range r.procs {
		pids = append(pids, p.cmd.Process.Pid)
	}

	return pids
}

// CPUSeconds is the user and system CPU time of every child so far.
func (r *Runner) CPUSeconds() (float64, error) {
	total := 0.0

	for _, pid := range r.PIDs() {
		s, err := cpuSeconds(pid)
		if err != nil {
			return 0, err
		}

		total += s
	}

	return total, nil
}

// RSSBytes is the resident memory of every child now.
func (r *Runner) RSSBytes() (int64, error) {
	var total int64

	for _, pid := range r.PIDs() {
		b, err := rssBytes(pid)
		if err != nil {
			return 0, err
		}

		total += b
	}

	return total, nil
}

func tail(path string, n int) string {
	b, err := os.ReadFile(path) //nolint: gosec // our own log
	if err != nil {
		return err.Error()
	}

	if len(b) > n {
		b = b[len(b)-n:]
	}

	return string(b)
}
