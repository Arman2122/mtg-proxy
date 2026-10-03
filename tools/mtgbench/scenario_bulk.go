package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// bulkChunk is one command's worth of a bulk transfer.
const bulkChunk = 1 << 20

// bulkWindow is what a bulk run moved: in the measured stretch, and in all,
// with the binary's CPU time over the measured stretch (NaN when it cannot be
// read).
type bulkWindow struct {
	bytes   int64
	elapsed time.Duration
	total   int64
	cpu     float64
}

func (w bulkWindow) rate() float64 { return float64(w.bytes) / w.elapsed.Seconds() }

func (w bulkWindow) sample() Sample {
	return Sample{
		"mbps":      w.rate() / 1e6,
		"cpu-s/gb":  w.cpu / (float64(w.bytes) / 1e9),
		"total-mib": float64(w.total) / (1 << 20),
	}
}

var bulkMetrics = []Metric{{Key: "mbps", Title: "MB/s"}, {Key: "cpu-s/gb", Title: "CPU-s per GB"}}

// runBulk moves data through every connection at once, for the warm-up and
// then the measured stretch, and reports the measured stretch. Every chunk is
// checked to the byte; any failure fails the run. cpu, when given, reads the
// binary's CPU seconds so far.
func runBulk(ctx context.Context, conns []io.ReadWriter, download bool, o Options, cpu func() (float64, error)) (bulkWindow, error) {
	var (
		moved atomic.Int64
		stop  = make(chan struct{})
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)

	for _, conn := range conns {
		wg.Go(func() {
			if err := pump(conn, download, bulkChunk, stop, &moved); err != nil {
				mu.Lock()
				first = firstErr(first, err)
				mu.Unlock()
			}
		})
	}

	readCPU := func() float64 {
		if cpu == nil {
			return math.NaN()
		}

		s, err := cpu()
		if err != nil {
			return math.NaN()
		}

		return s
	}

	wait := func(d time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err() //nolint: wrapcheck
		case <-time.After(d):
			return nil
		}
	}

	var w bulkWindow

	err := wait(o.Warmup)
	if err == nil {
		bytes0, cpu0, t0 := moved.Load(), readCPU(), time.Now()

		err = wait(o.Measure)

		w.bytes, w.cpu, w.elapsed = moved.Load()-bytes0, readCPU()-cpu0, time.Since(t0)
	}

	close(stop)
	wg.Wait()

	w.total = moved.Load()

	if first != nil {
		return w, first
	}

	return w, err
}

// firstErr keeps the first of two errors.
func firstErr(a, b error) error {
	if a != nil {
		return a
	}

	return b
}

// dialMany opens n connections through door, one per user in users (cycled),
// with a deadline that bounds the whole run.
func (b *Bench) dialMany(ctx context.Context, st *Stack, door Door, users []User, n int, deadline time.Time) ([]*Client, error) {
	clients := make([]*Client, 0, n)

	for i := range n {
		c, err := Dial(ctx, st.Setup, door, users[i%len(users)], clientIP(i))
		if err != nil {
			closeAll(clients)

			return nil, fmt.Errorf("connection %d of %d: %w", i+1, n, err)
		}

		if err := c.SetDeadline(deadline); err != nil {
			c.Close() //nolint: errcheck
			closeAll(clients)

			return nil, fmt.Errorf("cannot bound connection %d: %w", i+1, err)
		}

		clients = append(clients, c)
	}

	return clients, nil
}

func closeAll(clients []*Client) {
	for _, c := range clients {
		c.Close() //nolint: errcheck
	}
}

// clientIP is a documentation address (TEST-NET-2) per connection, for the
// WEB relay's X-Forwarded-For.
func clientIP(i int) string { return fmt.Sprintf("198.51.100.%d", 1+i%254) }

// bulk is one bulk run: n connections of users through door, one way.
func (b *Bench) bulk(ctx context.Context, door Door, users []User, n int, download bool) (Sample, error) {
	deadline := time.Now().Add(b.Opts.Warmup + b.Opts.Measure + time.Minute)

	clients, err := b.dialMany(ctx, b.Stack, door, users, n, deadline)
	if err != nil {
		return nil, err
	}
	defer closeAll(clients)

	conns := make([]io.ReadWriter, len(clients))
	for i, c := range clients {
		conns[i] = c
	}

	w, err := runBulk(ctx, conns, download, b.Opts, b.Stack.Runner.CPUSeconds)
	if err != nil {
		return nil, err
	}

	return w.sample(), nil
}

func direction(download bool) string {
	if download {
		return "download"
	}

	return "upload"
}

func conns(n int) string {
	if n == 1 {
		return "1 conn"
	}

	return fmt.Sprintf("%d conns", n)
}

func bulkScenario() scenario {
	return scenario{
		name: "bulk",
		about: "Every connection moves 1 MiB chunks, two commands in flight, each checked to the byte. " +
			"CPU is every process of the binary (the proxy, and the relay), per GB moved.",
		metrics: bulkMetrics,
		run: func(ctx context.Context, b *Bench) []Row {
			var rows []Row

			for _, door := range b.doors() {
				for _, n := range []int{1, 64} {
					for _, download := range []bool{true, false} {
						label := fmt.Sprintf("%s, %s, %s", b.label(door), conns(n), direction(download))

						rows = append(rows, b.cell(ctx, label, b.Opts.Runs, func(ctx context.Context) (Sample, error) {
							return b.bulk(ctx, door, []User{b.user(alice)}, n, download)
						}))
					}
				}
			}

			return rows
		},
	}
}

// The users a scenario names. alice has no cap; capped has one far above any
// rate this machine reaches; crowd are the 64 users of the contention row.
const (
	alice  = "alice"
	capped = "capped"
)

const crowdSize = 64

func crowdName(i int) string { return fmt.Sprintf("u%02d", i) }

// user is the setup's user by name. Every name asked for is configured for the
// stacks that run the scenario asking.
func (b *Bench) user(name string) User {
	for _, u := range b.Stack.Setup.Users {
		if u.Name == name {
			return u
		}
	}

	panic("mtgbench: no user " + name) //nolint: forbidigo // a scenario asked for a user its stack lacks
}

func (b *Bench) crowd() []User {
	users := make([]User, crowdSize)
	for i := range users {
		users[i] = b.user(crowdName(i))
	}

	return users
}

func contentionScenario() scenario {
	return scenario{
		name:    "contention",
		about:   "dd, 64 downloads: one user's 64 connections against 64 users of one each.",
		metrics: bulkMetrics,
		run: func(ctx context.Context, b *Bench) []Row {
			if !b.has(DoorDD) || b.Stack.Setup.Shaping != shapingRecord {
				return nil
			}

			return []Row{
				b.cell(ctx, "dd, 1 user × 64 conns", b.Opts.Runs, func(ctx context.Context) (Sample, error) {
					return b.bulk(ctx, DoorDD, []User{b.user(alice)}, crowdSize, true)
				}),
				b.cell(ctx, "dd, 64 users × 1 conn", b.Opts.Runs, func(ctx context.Context) (Sample, error) {
					return b.bulk(ctx, DoorDD, b.crowd(), crowdSize, true)
				}),
			}
		},
	}
}

func limiterScenario() scenario {
	return scenario{
		name:    "limiter",
		about:   "dd, 64 downloads: no cap, against a cap of 10 GB/s that never binds. The difference is the limiter's own cost.",
		metrics: bulkMetrics,
		run: func(ctx context.Context, b *Bench) []Row {
			if !b.has(DoorDD) || b.Stack.Setup.Shaping != shapingRecord {
				return nil
			}

			return []Row{
				b.cell(ctx, "dd, no cap", b.Opts.Runs, func(ctx context.Context) (Sample, error) {
					return b.bulk(ctx, DoorDD, []User{b.user(alice)}, crowdSize, true)
				}),
				b.cell(ctx, "dd, cap far above", b.Opts.Runs, func(ctx context.Context) (Sample, error) {
					return b.bulk(ctx, DoorDD, []User{b.user(capped)}, crowdSize, true)
				}),
			}
		},
	}
}
