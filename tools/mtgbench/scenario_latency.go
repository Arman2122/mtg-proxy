package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// handshakes is what a stretch of back-to-back connections came to.
type handshakes struct {
	connected, fronted, failed int64

	// firstByte is, per connection, the time from the start of its dial to
	// the first byte of the data centre's answer.
	firstByte []time.Duration

	// err is the first failure, for the report.
	err error
}

// runHandshakes opens whole connections back to back from workers goroutines
// for d: dial, a one-byte echo, close. A hello the proxy fronted is counted as
// fronted, apart from failures: the anti-replay cache takes about one hello in
// a thousand for a replay at these rates, and fronting it is the design.
func runHandshakes(ctx context.Context, workers int, d time.Duration, dial func(context.Context) (*Client, error)) handshakes {
	var (
		mu  sync.Mutex
		h   handshakes
		wg  sync.WaitGroup
		end = time.Now().Add(d)
	)

	for range workers {
		wg.Go(func() {
			for ctx.Err() == nil && time.Now().Before(end) {
				took, err := oneConnection(ctx, dial)

				mu.Lock()

				switch {
				case errors.Is(err, errFronted):
					h.fronted++
				case err != nil:
					h.failed++
					h.err = firstErr(h.err, err)
				default:
					h.connected++
					h.firstByte = append(h.firstByte, took)
				}

				mu.Unlock()
			}
		})
	}

	wg.Wait()

	return h
}

func oneConnection(ctx context.Context, dial func(context.Context) (*Client, error)) (time.Duration, error) {
	started := time.Now()

	c, err := dial(ctx)
	if err != nil {
		return 0, err
	}
	defer c.Close() //nolint: errcheck

	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return 0, fmt.Errorf("cannot bound the connection: %w", err)
	}

	if err := Echo(c, []byte{1}); err != nil {
		return 0, err
	}

	return time.Since(started), nil
}

// sample is h over a measured stretch of elapsed.
func (h handshakes) sample(elapsed time.Duration) Sample {
	return Sample{
		"conn/s":  float64(h.connected) / elapsed.Seconds(),
		"p50-ms":  percentile(h.firstByte, 0.50).Seconds() * 1e3,
		"p99-ms":  percentile(h.firstByte, 0.99).Seconds() * 1e3,
		"fronted": float64(h.fronted),
		"failed":  float64(h.failed),
	}
}

// percentile is the q-quantile of samples, which it leaves unsorted.
func percentile(samples []time.Duration, q float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}

	sorted := slices.Clone(samples)
	slices.Sort(sorted)

	return sorted[min(len(sorted)-1, int(q*float64(len(sorted))))]
}

// handshakeWorkers is how many connections are opened at once. Enough to keep
// the binary's core busy; mtgbench's own core is the other one.
const handshakeWorkers = 8

func handshakeScenario() scenario {
	return scenario{
		name: "handshake",
		about: "Whole connections back to back, 8 at a time: dial, a one-byte echo, close. " +
			"Connect-to-first-byte includes the proxy's SOCKS5 round trip to the data centre. " +
			"Fronted is hellos the anti-replay cache took for replays (by the client; the cover listener's own count beside it).",
		metrics: []Metric{
			{Key: "conn/s", Title: "connections/s"},
			{Key: "p50-ms", Title: "first byte p50 ms"},
			{Key: "p99-ms", Title: "p99 ms"},
			{Key: "fronted", Title: "fronted"},
			{Key: "cover", Title: "at the cover"},
		},
		run: func(ctx context.Context, b *Bench) []Row {
			rows := make([]Row, 0, len(b.doors()))

			for _, door := range b.doors() {
				dial := func(ctx context.Context) (*Client, error) {
					return Dial(ctx, b.Stack.Setup, door, b.user(alice), clientIP(0))
				}

				rows = append(rows, b.cell(ctx, b.label(door), b.Opts.Runs, func(ctx context.Context) (Sample, error) {
					runHandshakes(ctx, handshakeWorkers, b.Opts.Warmup, dial)

					cover0, started := b.Stack.Fronted(), time.Now()
					h := runHandshakes(ctx, handshakeWorkers, b.Opts.Measure, dial)
					elapsed := time.Since(started)

					if h.failed > 0 {
						return nil, fmt.Errorf("%d of %d connections failed: %w", h.failed, h.failed+h.connected+h.fronted, h.err)
					}

					s := h.sample(elapsed)
					s["cover"] = float64(b.Stack.Fronted() - cover0)

					return s, nil
				}))
			}

			return rows
		},
	}
}

// pingSize is the latency scenario's message, each way.
const pingSize = 100

// pingPong sends pingSize bytes and waits for them back, over and over, for
// the warm-up and then the measured stretch, and returns the measured round
// trips.
func pingPong(ctx context.Context, c *Client, o Options) ([]time.Duration, error) {
	message := make([]byte, pingSize)
	samples := make([]time.Duration, 0, 1<<16)

	for _, stretch := range []struct {
		d    time.Duration
		keep bool
	}{{o.Warmup, false}, {o.Measure, true}} {
		for end := time.Now().Add(stretch.d); time.Now().Before(end); {
			if err := ctx.Err(); err != nil {
				return nil, err //nolint: wrapcheck
			}

			started := time.Now()

			if err := Echo(c, message); err != nil {
				return nil, err
			}

			if stretch.keep {
				samples = append(samples, time.Since(started))
			}
		}
	}

	return samples, nil
}

func latencyScenario() scenario {
	return scenario{
		name: "latency",
		about: "One connection, 100 bytes to the data centre and 100 back, over and over. " +
			"Direct is the same with no proxy and no SOCKS5: a door's added latency is its figure minus that one. " +
			"Samples is how many round trips the percentiles rest on.",
		metrics: []Metric{
			{Key: "p50-us", Title: "p50 µs"},
			{Key: "p99-us", Title: "p99 µs"},
			{Key: "p999-us", Title: "p99.9 µs"},
			{Key: "n", Title: "samples"},
		},
		run: func(ctx context.Context, b *Bench) []Row {
			type target struct {
				label string
				dial  func(context.Context) (*Client, error)
			}

			var targets []target

			if b.Stack.Setup.Shaping == shapingRecord {
				targets = append(targets, target{"direct", func(ctx context.Context) (*Client, error) {
					return DialDirect(ctx, b.Stack.Setup)
				}})
			}

			for _, door := range b.doors() {
				targets = append(targets, target{b.label(door), func(ctx context.Context) (*Client, error) {
					return Dial(ctx, b.Stack.Setup, door, b.user(alice), clientIP(0))
				}})
			}

			rows := make([]Row, 0, len(targets))

			for _, t := range targets {
				rows = append(rows, b.cell(ctx, t.label, b.Opts.Runs, func(ctx context.Context) (Sample, error) {
					c, err := t.dial(ctx)
					if err != nil {
						return nil, err
					}
					defer c.Close() //nolint: errcheck

					if err := c.SetDeadline(time.Now().Add(b.Opts.Warmup + b.Opts.Measure + time.Minute)); err != nil {
						return nil, fmt.Errorf("cannot bound the connection: %w", err)
					}

					samples, err := pingPong(ctx, c, b.Opts)
					if err != nil {
						return nil, err
					}

					us := func(q float64) float64 { return float64(percentile(samples, q).Nanoseconds()) / 1e3 }

					return Sample{"p50-us": us(0.50), "p99-us": us(0.99), "p999-us": us(0.999), "n": float64(len(samples))}, nil
				}))
			}

			return rows
		},
	}
}
