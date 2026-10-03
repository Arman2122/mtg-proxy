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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
		bin      = flag.String("bin", "./mtg-proxy", "the mtg-proxy binary under test")
		smoke    = flag.Bool("smoke", false, "move 1 MiB each way through every door once, and stop")
		pin      = flag.Int("pin", noPin, "CPU core to pin the binary to with taskset (Linux); -1 leaves it unpinned")
		basePort = flag.Int("base-port", 47000, "first of the loopback ports the run uses (base..base+12)")
		shaping  = flag.String("shaping", "record", `the ee door's shaping: "record" or "burst"`)
		dir      = flag.String("dir", "", "where configs and logs go; a fresh temporary directory if empty")
	)

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	workDir := *dir
	if workDir == "" {
		var err error

		if workDir, err = os.MkdirTemp("", "mtgbench-"); err != nil {
			return fmt.Errorf("cannot make a work directory: %w", err)
		}

		defer os.RemoveAll(workDir) //nolint: errcheck
	}

	binary, err := filepath.Abs(*bin)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %w", *bin, err)
	}

	setup := Setup{
		Dir:      workDir,
		Users:    []User{NewUser("alice")},
		Doors:    AllDoors,
		Shaping:  *shaping,
		BasePort: *basePort,
	}

	if *smoke {
		return runSmoke(ctx, setup, binary, *pin)
	}

	return fmt.Errorf("nothing to do: pass -smoke")
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
