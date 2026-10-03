package main

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// idleWorkers is how many idle connections are opened at once.
const idleWorkers = 16

// openIdle opens n connections through door on st, each proven to reach the
// data centre with a one-byte echo, and leaves them open.
func openIdle(ctx context.Context, st *Stack, door Door, u User, n int) ([]*Client, error) {
	var (
		mu      sync.Mutex
		clients = make([]*Client, 0, n)
		first   error
		next    = make(chan int)
		wg      sync.WaitGroup
	)

	for range idleWorkers {
		wg.Go(func() {
			for i := range next {
				c, err := Dial(ctx, st.Setup, door, u, clientIP(i))
				if err == nil {
					err = c.SetDeadline(time.Now().Add(10 * time.Minute))
				}

				if err == nil {
					err = Echo(c, []byte{1})
				}

				mu.Lock()

				if err != nil {
					first = firstErr(first, fmt.Errorf("connection %d: %w", i+1, err))
				}

				if c != nil {
					clients = append(clients, c)
				}

				mu.Unlock()
			}
		})
	}

	for i := range n {
		mu.Lock()
		failed := first != nil
		mu.Unlock()

		if failed || ctx.Err() != nil {
			break
		}

		next <- i
	}

	close(next)
	wg.Wait()

	if first == nil {
		first = ctx.Err()
	}

	if first != nil {
		closeAll(clients)

		return nil, first
	}

	return clients, nil
}

// rssDelta is (after - before) per connection, in KiB, or NaN when the
// readings are not available here.
func rssDelta(before, after int64, errBefore, errAfter error, n int) float64 {
	if errBefore != nil || errAfter != nil {
		return math.NaN()
	}

	return float64(after-before) / float64(n) / 1024
}

func idleScenario() scenario {
	return scenario{
		name: "idle",
		about: "Connections opened and left open on a fresh process, each first proven with a one-byte echo. " +
			"RSS is every process of the binary; per connection is the growth over the process before it, divided by the count. " +
			"WEB is one session per connection.",
		metrics: []Metric{{Key: "kib/conn", Title: "RSS KiB per conn"}, {Key: "open-s", Title: "seconds to open"}},
		run: func(ctx context.Context, b *Bench) []Row {
			var rows []Row

			for _, door := range b.doors() {
				counts := []int{1000}
				if b.Stack.Setup.Shaping == shapingRecord && (door == DoorEE || door == DoorDD) {
					counts = append(counts, 5000)
				}

				for _, n := range counts {
					label := fmt.Sprintf("%s, %d conns", b.label(door), n)

					rows = append(rows, b.cell(ctx, label, b.Opts.Runs, func(ctx context.Context) (Sample, error) {
						return b.idle(ctx, door, n)
					}))
				}
			}

			return rows
		},
	}
}

func (b *Bench) idle(ctx context.Context, door Door, n int) (Sample, error) {
	st, err := b.Fresh(ctx)
	if err != nil {
		return nil, err
	}
	defer st.Close() //nolint: errcheck

	before, errBefore := st.Runner.RSSBytes()
	started := time.Now()

	clients, err := openIdle(ctx, st, door, b.user(alice), n)
	if err != nil {
		return nil, err
	}
	defer closeAll(clients)

	opened := time.Since(started)
	after, errAfter := st.Runner.RSSBytes()

	return Sample{"kib/conn": rssDelta(before, after, errBefore, errAfter, n), "open-s": opened.Seconds()}, nil
}

const (
	slowReaders = 64
	slowRate    = 100 << 10 // bytes per second, per reader
	slowFor     = 20 * time.Second
)

func slowReaderScenario() scenario {
	return scenario{
		name: "slow-reader",
		about: "64 ee connections on a fresh process whose clients read 100 KiB/s while the data centre sends as fast as it can, for 20 s, once. " +
			"RSS per connection should stay near the doppelganger's bound (about 512 KiB of queue) and not grow with time.",
		metrics: []Metric{
			{Key: "kib@5s", Title: "KiB per conn at 5 s"},
			{Key: "kib@end", Title: "at 20 s"},
			{Key: "kib-peak", Title: "peak"},
			{Key: "growth", Title: "growth 5→20 s"},
		},
		run: func(ctx context.Context, b *Bench) []Row {
			if !b.has(DoorEE) {
				return nil
			}

			return []Row{b.cell(ctx, b.label(DoorEE)+", 64 conns", 1, b.slowReaders)}
		},
	}
}

func (b *Bench) slowReaders(ctx context.Context) (Sample, error) {
	st, err := b.Fresh(ctx)
	if err != nil {
		return nil, err
	}
	defer st.Close() //nolint: errcheck

	before, errBefore := st.Runner.RSSBytes()

	clients, err := b.dialMany(ctx, st, DoorEE, []User{b.user(alice)}, slowReaders, time.Now().Add(slowFor+time.Minute))
	if err != nil {
		return nil, err
	}

	var (
		stop = make(chan struct{})
		wg   sync.WaitGroup
		mu   sync.Mutex
		bad  error
	)

	for _, c := range clients {
		// More than will ever be read: the data centre sends until the
		// connection closes.
		if _, err := c.Write(command(cmdDownload, 1<<40)); err != nil {
			closeAll(clients)

			return nil, fmt.Errorf("cannot start a download: %w", err)
		}

		wg.Go(func() {
			if err := readSlowly(c, stop); err != nil {
				mu.Lock()
				bad = firstErr(bad, err)
				mu.Unlock()
			}
		})
	}

	var perSecond []float64

	for range int(slowFor / time.Second) {
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}

		after, errAfter := st.Runner.RSSBytes()
		perSecond = append(perSecond, rssDelta(before, after, errBefore, errAfter, slowReaders))
	}

	close(stop)
	closeAll(clients)
	wg.Wait()

	if bad != nil {
		return nil, bad
	}

	if err := ctx.Err(); err != nil {
		return nil, err //nolint: wrapcheck
	}

	peak := math.Inf(-1)
	for _, v := range perSecond {
		peak = math.Max(peak, v)
	}

	at5, end := perSecond[4], perSecond[len(perSecond)-1]

	return Sample{"kib@5s": at5, "kib@end": end, "kib-peak": peak, "growth": end - at5}, nil
}

// readSlowly reads c at slowRate until stop, checking what it reads is the
// data centre's zeros. An error before stop is the proxy failing a slow
// client, which is a finding; after it, the connection is being closed.
func readSlowly(c *Client, stop <-chan struct{}) error {
	buf := make([]byte, 16<<10)
	started := time.Now()

	for got := 0.0; ; {
		select {
		case <-stop:
			return nil
		default:
		}

		allowed := time.Since(started).Seconds()*slowRate - got
		if allowed < 1 {
			time.Sleep(20 * time.Millisecond)

			continue
		}

		n, err := c.Read(buf[:min(len(buf), int(allowed))])
		if n > 0 && !bytes.Equal(buf[:n], zeros[:n]) {
			return fmt.Errorf("slow reader: %w", errCorrupt)
		}

		got += float64(n)

		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return fmt.Errorf("a slow reader's connection failed: %w", err)
			}
		}
	}
}
