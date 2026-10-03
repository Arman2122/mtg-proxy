package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// Stack is one standing run: mtgbench's data centres and cover listener, and
// the binary's proxy and relay configured to use them.
type Stack struct {
	Setup  Setup
	DC     *DataCentre
	Direct *DataCentre
	Runner *Runner

	cover   net.Listener
	fronted atomic.Int64
}

// Fronted counts connections the proxy handed to the cover listener: a hello
// it refused, which in a run means an anti-replay false positive.
func (st *Stack) Fronted() int64 { return st.fronted.Load() }

// StartStack checks every port is free, starts mtgbench's side, writes the
// config and starts the binary pinned to core, and waits until it listens.
func StartStack(ctx context.Context, s Setup, bin string, core int) (*Stack, error) {
	for _, addr := range s.Ports() {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("port %s is not free; nothing was started: %w", addr, err)
		}

		ln.Close() //nolint: errcheck
	}

	st := &Stack{Setup: s}

	var err error

	if st.DC, err = StartSOCKS(ctx, s.SOCKSAddr()); err != nil {
		return nil, err
	}

	if st.Direct, err = StartDirectDC(ctx, s.DirectAddr()); err != nil {
		st.Close() //nolint: errcheck

		return nil, err
	}

	if st.cover, err = (&net.ListenConfig{}).Listen(ctx, "tcp", s.CoverAddr()); err != nil {
		st.Close() //nolint: errcheck

		return nil, fmt.Errorf("cannot listen for fronting: %w", err)
	}

	go st.serveCover()

	cfg, err := WriteConfig(s)
	if err != nil {
		st.Close() //nolint: errcheck

		return nil, err
	}

	web := false

	for _, d := range s.Doors {
		web = web || d == DoorWeb
	}

	if st.Runner, err = StartRunner(ctx, s.Dir, bin, cfg, core, web); err != nil {
		st.Close() //nolint: errcheck

		return nil, err
	}

	ready := []string{s.APIAddr(), s.ObfuscatedAddr()}
	if web {
		ready = append(ready, s.RelayAddr())
	}

	if err := st.Runner.WaitReady(ctx, ready, 15*time.Second); err != nil {
		st.Close() //nolint: errcheck

		return nil, err
	}

	// The ee port last, and once: a probe there connects and hangs up without
	// a hello, and the proxy fronts it, as it should. That one front is the
	// probe's, and it doubles as a check that fronting works at all. Then the
	// count is the run's.
	if err := st.Runner.WaitReady(ctx, []string{s.EEAddr()}, 15*time.Second); err != nil {
		st.Close() //nolint: errcheck

		return nil, err
	}

	if err := st.waitFronted(ctx, 1, 5*time.Second); err != nil {
		st.Close() //nolint: errcheck

		return nil, err
	}

	st.fronted.Store(0)

	return st, nil
}

var errNotFronted = errors.New("the readiness probe was never fronted: is fronting broken?")

func (st *Stack) waitFronted(ctx context.Context, n int64, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for st.fronted.Load() < n {
		if time.Now().After(deadline) {
			return errNotFronted
		}

		select {
		case <-ctx.Done():
			return ctx.Err() //nolint: wrapcheck
		case <-time.After(10 * time.Millisecond):
		}
	}

	return nil
}

func (st *Stack) serveCover() {
	for {
		c, err := st.cover.Accept()
		if err != nil {
			return
		}

		st.fronted.Add(1)
		c.Close() //nolint: errcheck
	}
}

// Close stops the binary first, then mtgbench's side.
func (st *Stack) Close() error {
	if st.Runner != nil {
		st.Runner.Close() //nolint: errcheck
	}

	if st.cover != nil {
		st.cover.Close() //nolint: errcheck
	}

	if st.Direct != nil {
		st.Direct.Close() //nolint: errcheck
	}

	if st.DC != nil {
		st.DC.Close() //nolint: errcheck
	}

	return nil
}
