// Command mtgbench runs the real mtg-proxy binary under load: Tier B of the
// measurement spec (docs/superpowers/specs/2026-10-02-performance-measurement-design.md).
//
// It starts the binary with a config of its own, so that the binary's
// Telegram is mtgbench's SOCKS5 data centre and nothing leaves the machine,
// then drives every door with real clients and reads CPU and memory from
// /proc. It is not part of the release binary.
//
// It shares hosts with other people's services, so it stops whatever it
// starts on every way a run can end, and on Linux its children die with it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mtgbench:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		bin       = flag.String("bin", "./mtg-proxy", "the mtg-proxy binary under test")
		smoke     = flag.Bool("smoke", false, "move 1 MiB each way through every door once, and stop")
		pin       = flag.Int("pin", noPin, "CPU core to pin the binary to with taskset (Linux); -1 leaves it unpinned")
		basePort  = flag.Int("base-port", 47000, fmt.Sprintf("first of the loopback ports the run uses (base..base+%d)", portSpan))
		shapings  = flag.String("shaping", "record,burst", `the ee door's shapings, each its own process: "record", "burst" or both`)
		dir       = flag.String("dir", "", "where configs and logs go; a fresh temporary directory if empty")
		scenarios = flag.String("scenarios", "all", "the scenarios to run, comma-separated: bulk, handshake, latency, idle, contention, limiter, slow-reader, caps, accounting")
		doorList  = flag.String("doors", "all", "the doors to run, comma-separated: ee, dd, plain, web")
		warmup    = flag.Duration("warmup", 2*time.Second, "each run's warm-up, whose figures are dropped")
		measure   = flag.Duration("measure", 5*time.Second, "each run's measured stretch")
		runs      = flag.Int("runs", 3, "runs per cell; the report gives their median and range")
		out       = flag.String("out", "", "a directory to write tierB.md and tierB.json into; the Markdown also goes to stdout")
	)

	flag.Parse()

	if *basePort < 1024 || *basePort > 65535-portSpan {
		return fmt.Errorf("-base-port %d: the run needs %d..%d", *basePort, *basePort, *basePort+portSpan)
	}

	shapingList := strings.Split(*shapings, ",")
	for _, s := range shapingList {
		if s != shapingRecord && s != shapingBurst {
			return fmt.Errorf("-shaping %q: want record, burst or both", s)
		}
	}

	selected, err := selectScenarios(*scenarios)
	if err != nil {
		return err
	}

	doors, err := selectDoors(*doorList)
	if err != nil {
		return err
	}

	opts := Options{Warmup: *warmup, Measure: *measure, Runs: *runs}
	if opts.Runs < 1 || opts.Measure <= 0 || opts.Warmup < 0 {
		return fmt.Errorf("-runs %d, -measure %s, -warmup %s: want at least one run of some length", opts.Runs, opts.Measure, opts.Warmup)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	workDir := *dir
	if workDir == "" {
		if workDir, err = os.MkdirTemp("", "mtgbench-"); err != nil {
			return fmt.Errorf("cannot make a work directory: %w", err)
		}

		defer os.RemoveAll(workDir) //nolint: errcheck
	}

	binary, err := filepath.Abs(*bin)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %w", *bin, err)
	}

	if *smoke {
		for _, shaping := range shapingList {
			setup, err := standingSetup(workDir, shaping, *basePort, doors, false)
			if err != nil {
				return err
			}

			if len(setup.Doors) == 0 {
				continue
			}

			if err := runSmoke(ctx, setup, binary, *pin); err != nil {
				return err
			}
		}

		return nil
	}

	if *out != "" {
		if err := prepareOut(*out); err != nil {
			return err
		}
	}

	report := Report{Started: time.Now(), Binary: binary, Pin: *pin, Options: opts, Limits: limits(*pin)}

	for _, shaping := range shapingList {
		setup, err := standingSetup(workDir, shaping, *basePort, doors, true)
		if err != nil {
			return err
		}

		if len(setup.Doors) == 0 {
			continue
		}

		stack, err := StartStack(ctx, setup, binary, *pin)
		if err != nil {
			return err
		}

		bench := &Bench{Stack: stack, Opts: opts, Log: os.Stderr, Fresh: freshStacks(setup, binary, *pin)}
		report.Tables = runScenarios(ctx, bench, selected, report.Tables)

		stack.Close() //nolint: errcheck
	}

	if err := report.markdown(os.Stdout); err != nil {
		return fmt.Errorf("cannot print the report: %w", err)
	}

	// Every way the run fell short is reported: a report that could not be
	// written does not hide the rows that failed.
	errs := []error{ctx.Err()}

	if *out != "" {
		errs = append(errs, report.write(*out))
	}

	if failed := failures(report.Tables); len(failed) > 0 {
		errs = append(errs, fmt.Errorf("%d row(s) failed: %s", len(failed), strings.Join(failed, "; "))) //nolint: err113
	}

	return errors.Join(errs...)
}

// standingSetup is the configuration of one shaping's stack. The record stack
// serves every door and, for the scenarios, the capped user and the crowd; the
// burst stack serves ee alone, the one door shaping changes.
func standingSetup(workDir, shaping string, basePort int, doors []Door, scenarios bool) (Setup, error) {
	token, err := NewAPIToken()
	if err != nil {
		return Setup{}, err
	}

	dir := filepath.Join(workDir, shaping)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Setup{}, fmt.Errorf("cannot make %s: %w", dir, err)
	}

	setup := Setup{
		Dir:      dir,
		Users:    []User{NewUser(alice)},
		Doors:    AllDoors,
		Shaping:  shaping,
		BasePort: basePort,
		APIToken: token,
	}

	if shaping == shapingBurst {
		setup.Doors = []Door{DoorEE}
	}

	setup.Doors = slices.DeleteFunc(setup.Doors, func(d Door) bool { return !slices.Contains(doors, d) })

	if scenarios {
		setup.Users = append(setup.Users, NewUser(acctUser))
	}

	if scenarios && shaping == shapingRecord {
		setup.Users = append(setup.Users, NewUser(capped))
		setup.Caps = map[string]Caps{capped: {Speed: "10GB"}}

		for i := range crowdSize {
			setup.Users = append(setup.Users, NewUser(crowdName(i)))
		}

		for _, kind := range capKinds {
			for _, mib := range capSizes {
				setup.Users = append(setup.Users, NewUser(capUser(kind, mib)))
				setup.Caps[capUser(kind, mib)] = capFor(kind, mib)
			}
		}
	}

	return setup, nil
}

// selectDoors picks doors from a comma-separated list, or all.
func selectDoors(list string) ([]Door, error) {
	if list == "" || list == "all" {
		return AllDoors, nil
	}

	var doors []Door

	for name := range strings.SplitSeq(list, ",") {
		door := Door(strings.TrimSpace(name))
		if !slices.Contains(AllDoors, door) {
			return nil, fmt.Errorf("no door %q: want ee, dd, plain or web", name) //nolint: err113
		}

		doors = append(doors, door)
	}

	return doors, nil
}

// freshStacks starts stacks like setup's on the ports beside it, one at a time:
// each is closed before the next starts.
func freshStacks(setup Setup, bin string, core int) func(context.Context) (*Stack, error) {
	return func(ctx context.Context) (*Stack, error) {
		token, err := NewAPIToken()
		if err != nil {
			return nil, err
		}

		fresh := setup
		fresh.BasePort += freshOffset
		fresh.Dir = setup.Dir + "-fresh"
		fresh.APIToken = token

		if err := os.MkdirAll(fresh.Dir, 0o750); err != nil {
			return nil, fmt.Errorf("cannot make %s: %w", fresh.Dir, err)
		}

		return StartStack(ctx, fresh, bin, core)
	}
}

// limits are stated with every result.
func limits(pin int) []string {
	l := []string{
		"Loopback on one machine: these are the binary's own costs, not the network's.",
		"CPU and RSS are every process of the binary: the proxy, and the WEB relay beside it.",
		"Handshake times include the proxy's SOCKS5 round trip to mtgbench's data centre.",
		"ee unpaced and the ad-tag leg are measured in Tier A only.",
	}

	if pin == noPin {
		l = append(l, "Not pinned: the figures are per machine, not per core.")
	} else {
		l = append(l, fmt.Sprintf("The binary is pinned to core %d; run mtgbench on another, so the figures are per core.", pin))
	}

	if runtime.GOOS != "linux" {
		l = append(l, "CPU and memory read n/a: they come from Linux /proc.")
	}

	return l
}

// runSmoke moves 1 MiB each way and one echo through every door, byte-exact,
// against the real binary.
func runSmoke(ctx context.Context, s Setup, bin string, core int) error {
	stack, err := StartStack(ctx, s, bin, core)
	if err != nil {
		return err
	}
	defer stack.Close() //nolint: errcheck

	var report []string

	for _, door := range s.Doors {
		if err := smokeDoor(ctx, s, door, s.Users[0]); err != nil {
			return fmt.Errorf("%s: %w", doorLabel(door, s.Shaping), err)
		}

		report = append(report, doorLabel(door, s.Shaping)+" ok")
	}

	fmt.Println("smoke:", strings.Join(report, ", "))

	if f := stack.Fronted(); f > 0 {
		fmt.Printf("smoke: %d connection(s) fronted\n", f)
	}

	return nil
}

func smokeDoor(ctx context.Context, s Setup, door Door, u User) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client, err := Dial(ctx, s, door, u, "198.51.100.7")
	if err != nil {
		return err
	}
	defer client.Close() //nolint: errcheck

	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return fmt.Errorf("cannot set a deadline: %w", err)
	}

	if err := Download(client, 1<<20); err != nil {
		return err
	}

	if err := Upload(client, 1<<20); err != nil {
		return err
	}

	return Echo(client, make([]byte, 100))
}

// doorLabel names ee by its shaping, as the reports do.
func doorLabel(door Door, shaping string) string {
	if door == DoorEE {
		return "ee-" + shaping
	}

	return string(door)
}
