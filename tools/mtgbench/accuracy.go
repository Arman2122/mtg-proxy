package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errUndercounted = errors.New("the proxy counted less than the client received")
	errOvercounted  = errors.New("the proxy counted more than the data centre sent")
	errMiscounted   = errors.New("a clean transfer was not counted exactly")
)

// accuracy is achieved over target across the measured seconds.
type accuracy struct{ mean, p10, p90 float64 }

// capAccuracy is achieved over target for every second but the first: the
// speed limiter starts a user with one second of burst, so the first second
// runs above the cap by design.
func capAccuracy(perSecond []float64, target float64) accuracy {
	if len(perSecond) < 2 {
		return accuracy{math.NaN(), math.NaN(), math.NaN()}
	}

	ratios := make([]float64, 0, len(perSecond)-1)
	sum := 0.0

	for _, v := range perSecond[1:] {
		ratios = append(ratios, v/target)
		sum += v / target
	}

	slices.Sort(ratios)

	at := func(q float64) float64 { return ratios[min(len(ratios)-1, int(q*float64(len(ratios))))] }

	return accuracy{mean: sum / float64(len(ratios)), p10: at(0.10), p90: at(0.90)}
}

// jain is Jain's fairness index, (Σx)² / (n·Σx²): 1 when every share is
// equal, 1/n when one has everything.
func jain(shares []float64) float64 {
	var sum, squares float64

	for _, x := range shares {
		sum += x
		squares += x * x
	}

	if squares == 0 {
		return 1
	}

	return sum * sum / (float64(len(shares)) * squares)
}

// abruptVerdict judges the counters after a client vanished mid-download. The
// proxy counts a byte when its write to the client returns, so bytes still in
// buffers on the way are counted and never received: counted may exceed
// received. It may not be less, and it may not exceed what the data centre
// sent, give or take one of the data centre's writes, which is counted only
// once it completes.
func abruptVerdict(received, counted, sent int64) error {
	switch {
	case counted < received:
		return fmt.Errorf("%w: %d of %d", errUndercounted, counted, received)
	case counted > sent+dcChunk:
		return fmt.Errorf("%w: %d of %d", errOvercounted, counted, sent)
	}

	return nil
}

// traffic is payload one way and the other, from the client's side: written
// is what the client sent, read what it received.
type traffic struct{ written, read int64 }

type accounting struct {
	sample Sample
	err    error
}

// handshakeFrame is the obfuscated2 frame a client sends first. The proxy
// reads it before it counts anything; the WEB relay carries it as payload.
const handshakeFrame = 64

// accountingDiff compares what a client moved with what the proxy, and for
// WEB the relay, counted. A clean transfer must match to the byte.
func accountingDiff(client, proxy traffic, relay *traffic) accounting {
	s := Sample{
		"in-diff":  float64(proxy.written - client.written),
		"out-diff": float64(proxy.read - client.read),
	}

	if relay != nil {
		s["up-diff"] = float64(relay.written - client.written - handshakeFrame)
		s["down-diff"] = float64(relay.read - client.read)
	}

	for _, v := range s {
		if v != 0 {
			return accounting{sample: s, err: fmt.Errorf("%w: %s", errMiscounted, sampleLine(s))}
		}
	}

	return accounting{sample: s}
}

// countedConn counts the payload a client writes and reads.
type countedConn struct {
	io.ReadWriter

	written, read int64
}

func (c *countedConn) Write(p []byte) (int, error) {
	n, err := c.ReadWriter.Write(p)
	c.written += int64(n)

	return n, err //nolint: wrapcheck
}

func (c *countedConn) Read(p []byte) (int, error) {
	n, err := c.ReadWriter.Read(p)
	c.read += int64(n)

	return n, err //nolint: wrapcheck
}

var statsClient = &http.Client{Timeout: 5 * time.Second}

func getJSON(ctx context.Context, url, token string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("cannot ask %s: %w", url, err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := statsClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot ask %s: %w", url, err)
	}
	defer resp.Body.Close() //nolint: errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", url, resp.Status) //nolint: err113
	}

	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("cannot read %s: %w", url, err)
	}

	return nil
}

// userTraffic is one user's counters from the proxy's management API, in the
// client's terms: bytes_in is what the user wrote, bytes_out what it read.
func userTraffic(ctx context.Context, s Setup, name string) (traffic, error) {
	var doc struct {
		Users map[string]struct {
			BytesIn  int64 `json:"bytes_in"`
			BytesOut int64 `json:"bytes_out"`
		} `json:"users"`
	}

	if err := getJSON(ctx, "http://"+s.APIAddr()+"/stats", s.APIToken, &doc); err != nil {
		return traffic{}, err
	}

	u, ok := doc.Users[name]
	if !ok {
		// A user with no connection yet may not be listed: nothing counted.
		return traffic{}, nil
	}

	return traffic{written: u.BytesIn, read: u.BytesOut}, nil
}

// relayTraffic is the WEB relay's payload counters: up is what clients wrote.
func relayTraffic(ctx context.Context, s Setup) (traffic, error) {
	var doc struct {
		Bytes struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		} `json:"bytes"`
	}

	if err := getJSON(ctx, "http://"+s.RelayStatsAddr()+"/stats", "", &doc); err != nil {
		return traffic{}, err
	}

	return traffic{written: doc.Bytes.Up, read: doc.Bytes.Down}, nil
}

func (t traffic) minus(o traffic) traffic {
	return traffic{written: t.written - o.written, read: t.read - o.read}
}

// counters is the proxy's view of a user and, for WEB, the relay's.
type counters struct {
	proxy traffic
	relay *traffic
}

func (b *Bench) counters(ctx context.Context, door Door, user string) (counters, error) {
	proxy, err := userTraffic(ctx, b.Stack.Setup, user)
	if err != nil {
		return counters{}, err
	}

	c := counters{proxy: proxy}

	if door == DoorWeb {
		relay, err := relayTraffic(ctx, b.Stack.Setup)
		if err != nil {
			return counters{}, err
		}

		c.relay = &relay
	}

	return c, nil
}

func (c counters) minus(o counters) counters {
	d := counters{proxy: c.proxy.minus(o.proxy)}

	if c.relay != nil && o.relay != nil {
		relay := c.relay.minus(*o.relay)
		d.relay = &relay
	}

	return d
}

// settled polls the counters until done says they are final, or until they
// have not moved for a second, or five seconds pass.
func (b *Bench) settled(ctx context.Context, door Door, user string, done func(counters) bool) (counters, error) {
	var (
		last  counters
		still = time.Now()
	)

	for deadline := time.Now().Add(5 * time.Second); ; {
		c, err := b.counters(ctx, door, user)
		if err != nil {
			return counters{}, err
		}

		switch {
		case done(c):
			return c, nil
		case c.proxy != last.proxy:
			last, still = c, time.Now()
		case time.Since(still) > time.Second || time.Now().After(deadline):
			return c, nil
		}

		select {
		case <-ctx.Done():
			return counters{}, ctx.Err() //nolint: wrapcheck
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// The accounting scenario's transfers.
const (
	acctUp     = 8 << 20
	acctDown   = 16 << 20
	abruptAsk  = 64 << 20
	abruptRead = 4 << 20
	acctUser   = "acct"
)

func accountingScenario() scenario {
	return scenario{
		name: "accounting",
		about: "Clean: one connection uploads 8 MiB and downloads 16 MiB; the proxy's /stats bytes_in and bytes_out, " +
			"and for WEB the relay's bytes.up and bytes.down (less the client's 64-byte obfuscated2 frame), " +
			"minus what the client moved. Every difference must be 0. " +
			"Abrupt: the client asks for 64 MiB, reads 4 MiB and resets; the proxy may have counted bytes still in buffers, " +
			"so counted ≥ received and counted ≤ what the data centre sent is the bound, and the gap is reported.",
		metrics: []Metric{
			{Key: "in-diff", Title: "bytes_in − written", Count: true},
			{Key: "out-diff", Title: "bytes_out − read", Count: true},
			{Key: "up-diff", Title: "relay up − written", Count: true},
			{Key: "down-diff", Title: "relay down − read", Count: true},
			{Key: "gap-kib", Title: "abrupt: counted − received KiB"},
		},
		run: func(ctx context.Context, b *Bench) []Row {
			rows := make([]Row, 0, 2*len(b.doors()))

			for _, door := range b.doors() {
				rows = append(rows,
					b.cell(ctx, b.label(door)+", clean", b.Opts.Runs, func(ctx context.Context) (Sample, error) {
						return b.cleanAccounting(ctx, door)
					}),
					b.cell(ctx, b.label(door)+", abrupt", b.Opts.Runs, func(ctx context.Context) (Sample, error) {
						return b.abruptAccounting(ctx, door)
					}),
				)
			}

			return rows
		},
	}
}

func (b *Bench) cleanAccounting(ctx context.Context, door Door) (Sample, error) {
	before, err := b.counters(ctx, door, acctUser)
	if err != nil {
		return nil, err
	}

	c, err := Dial(ctx, b.Stack.Setup, door, b.user(acctUser), clientIP(0))
	if err != nil {
		return nil, err
	}

	if err := c.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		c.Close() //nolint: errcheck

		return nil, fmt.Errorf("cannot bound the connection: %w", err)
	}

	client := &countedConn{ReadWriter: c}

	err = Upload(client, acctUp)
	if err == nil {
		err = Download(client, acctDown)
	}

	c.Close() //nolint: errcheck

	if err != nil {
		return nil, err
	}

	moved := traffic{written: client.written, read: client.read}

	after, err := b.settled(ctx, door, acctUser, func(c counters) bool {
		return c.minus(before).proxy == moved
	})
	if err != nil {
		return nil, err
	}

	d := after.minus(before)
	result := accountingDiff(moved, d.proxy, d.relay)

	return result.sample, result.err
}

func (b *Bench) abruptAccounting(ctx context.Context, door Door) (Sample, error) {
	before, err := b.counters(ctx, door, acctUser)
	if err != nil {
		return nil, err
	}

	sentBefore := b.Stack.DC.BytesSent()

	c, err := Dial(ctx, b.Stack.Setup, door, b.user(acctUser), clientIP(0))
	if err != nil {
		return nil, err
	}

	if err := c.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		c.Close() //nolint: errcheck

		return nil, fmt.Errorf("cannot bound the connection: %w", err)
	}

	client := &countedConn{ReadWriter: c}

	_, err = client.Write(command(cmdDownload, abruptAsk))
	if err == nil {
		err = readZeros(client, abruptRead, make([]byte, clientChunk), nil)
	}

	c.Close() //nolint: errcheck // a reset: the client is gone, buffers and all

	if err != nil {
		return nil, err
	}

	// Nothing says when the proxy is done with a vanished client: wait for its
	// counters to stop moving.
	after, err := b.settled(ctx, door, acctUser, func(counters) bool { return false })
	if err != nil {
		return nil, err
	}

	counted := after.minus(before).proxy.read
	sent := b.Stack.DC.BytesSent() - sentBefore

	if err := abruptVerdict(client.read, counted, sent); err != nil {
		return nil, err
	}

	return Sample{"gap-kib": float64(counted-client.read) / 1024}, nil
}

// The speed-cap scenario's users: a cap of 1 or 10 MiB/s on speed (both
// directions together), speed-up or speed-down.
var (
	capKinds = []string{"speed", "speed-up", "speed-down"}
	capSizes = []int{1, 10}
)

const (
	capConns = 8

	// capChunk is a capped transfer's command size: small, so the two in
	// flight per connection put little ahead of the cap at the start and
	// leave little to finish at the end.
	capChunk = 64 << 10
)

func capUser(kind string, mib int) string { return fmt.Sprintf("%s-%d", kind, mib) }

func capFor(kind string, mib int) Caps {
	rate := fmt.Sprintf("%dMB", mib)

	switch kind {
	case "speed-up":
		return Caps{Up: rate}
	case "speed-down":
		return Caps{Down: rate}
	}

	return Caps{Speed: rate}
}

func capsScenario() scenario {
	return scenario{
		name: "caps",
		about: "One user, 8 connections, against a cap of 1 or 10 MiB/s. speed-up is measured uploading, " +
			"speed and speed-down downloading. Delivered bytes are sampled every second and the first (burst) second is dropped. " +
			"Achieved over target per second, and Jain's fairness index across the user's connections (1 is equal shares).",
		metrics: []Metric{
			{Key: "mean", Title: "achieved/target mean"},
			{Key: "p10", Title: "p10"},
			{Key: "p90", Title: "p90"},
			{Key: "jain", Title: "fairness"},
		},
		run: func(ctx context.Context, b *Bench) []Row {
			if b.Stack.Setup.Shaping != shapingRecord {
				return nil
			}

			var rows []Row

			for _, door := range b.doors() {
				if door == DoorPlain {
					continue
				}

				for _, kind := range capKinds {
					for _, mib := range capSizes {
						label := fmt.Sprintf("%s, %s %d MiB/s", b.label(door), kind, mib)

						rows = append(rows, b.cell(ctx, label, b.Opts.Runs, func(ctx context.Context) (Sample, error) {
							return b.capped(ctx, door, kind, mib)
						}))
					}
				}
			}

			return rows
		},
	}
}

func (b *Bench) capped(ctx context.Context, door Door, kind string, mib int) (Sample, error) {
	seconds := 1 + max(3, int(b.Opts.Measure/time.Second))
	download := kind != "speed-up"

	clients, err := b.dialMany(ctx, b.Stack, door, []User{b.user(capUser(kind, mib))}, capConns,
		time.Now().Add(time.Duration(seconds)*time.Second+time.Minute))
	if err != nil {
		return nil, err
	}
	defer closeAll(clients)

	var (
		moved = make([]atomic.Int64, len(clients))
		stop  = make(chan struct{})
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)

	for i, c := range clients {
		wg.Go(func() {
			if err := pump(c, download, capChunk, stop, &moved[i]); err != nil {
				mu.Lock()
				first = firstErr(first, err)
				mu.Unlock()
			}
		})
	}

	perSecond := make([]float64, 0, seconds)
	perConn := make([]float64, len(clients))
	last := make([]int64, len(clients))

	for second := range seconds {
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}

		total := 0.0

		for i := range moved {
			now := moved[i].Load()
			total += float64(now - last[i])

			if second > 0 {
				perConn[i] += float64(now - last[i])
			}

			last[i] = now
		}

		perSecond = append(perSecond, total)
	}

	close(stop)
	wg.Wait()

	if first != nil {
		return nil, first
	}

	if err := ctx.Err(); err != nil {
		return nil, err //nolint: wrapcheck
	}

	a := capAccuracy(perSecond, float64(mib<<20))

	return Sample{"mean": a.mean, "p10": a.p10, "p90": a.p90, "jain": jain(perConn)}, nil
}
