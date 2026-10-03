package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Options are a run's timings: every cell runs Runs times, each a warm-up
// whose figures are dropped and then a measured stretch.
type Options struct {
	Warmup  time.Duration `json:"warmup"`
	Measure time.Duration `json:"measure"`
	Runs    int           `json:"runs"`
}

// Sample is one run's figures for one row, by metric key. NaN is a figure this
// machine cannot read (CPU and memory off Linux).
type Sample map[string]float64

// MarshalJSON writes a figure that cannot be read, or has no value (a rate
// over nothing), as null: JSON has no NaN.
func (s Sample) MarshalJSON() ([]byte, error) {
	out := make(map[string]*float64, len(s))

	for k, v := range s {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			out[k] = nil

			continue
		}

		out[k] = &v
	}

	return json.Marshal(out) //nolint: wrapcheck
}

// Row is one line of a table: a door, and what was varied, with a sample per
// run -- or the error that ended it.
type Row struct {
	Label   string   `json:"label"`
	Samples []Sample `json:"samples,omitempty"`
	Err     string   `json:"error,omitempty"`
}

// Metric is one column.
type Metric struct {
	Key   string `json:"key"`
	Title string `json:"title"`

	// Count is a metric that is a number of things, shown without decimals.
	Count bool `json:"count,omitempty"`
}

// Table is one scenario's results.
type Table struct {
	Scenario string   `json:"scenario"`
	About    string   `json:"about"`
	Metrics  []Metric `json:"metrics"`
	Rows     []Row    `json:"rows"`
}

// printer writes to w and keeps the first error, so a report that cannot be
// written says so once, at the end, instead of at every line.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

// markdown writes t as a table of medians with their spread across runs.
func (t Table) markdown(w io.Writer) error {
	p := &printer{w: w}
	t.print(p)

	return p.err
}

func (t Table) print(p *printer) {
	p.printf("### %s\n\n", t.Scenario)

	if t.About != "" {
		p.printf("%s\n\n", t.About)
	}

	header, rule := "| |", "|---|"
	for _, m := range t.Metrics {
		header += " " + m.Title + " |"
		rule += "---|"
	}

	p.printf("%s\n%s\n", header, rule)

	for _, r := range t.Rows {
		if r.Err != "" {
			p.printf("| %s | failed: %s |\n", r.Label, strings.ReplaceAll(r.Err, "|", "/"))

			continue
		}

		cells := make([]string, 0, len(t.Metrics))
		for _, m := range t.Metrics {
			cells = append(cells, summarize(r.Samples, m))
		}

		p.printf("| %s | %s |\n", r.Label, strings.Join(cells, " | "))
	}

	p.printf("\n")
}

// summarize is the median of key across samples, with the range when the runs
// disagree: "200 (100–300)".
func summarize(samples []Sample, m Metric) string {
	values := make([]float64, 0, len(samples))

	for _, s := range samples {
		if v, ok := s[m.Key]; ok && !math.IsNaN(v) {
			values = append(values, v)
		}
	}

	if len(values) == 0 {
		return "n/a"
	}

	slices.Sort(values)

	median := values[len(values)/2]
	if len(values)%2 == 0 {
		median = (values[len(values)/2-1] + values[len(values)/2]) / 2
	}

	format := num
	if m.Count {
		format = func(v float64) string { return fmt.Sprintf("%.0f", v) }
	}

	if values[0] == values[len(values)-1] {
		return format(median)
	}

	return fmt.Sprintf("%s (%s–%s)", format(median), format(values[0]), format(values[len(values)-1]))
}

func num(v float64) string {
	switch a := math.Abs(v); {
	case a >= 100:
		return fmt.Sprintf("%.0f", v)
	case a >= 10:
		return fmt.Sprintf("%.1f", v)
	case a >= 0.1:
		return fmt.Sprintf("%.2f", v)
	default:
		return fmt.Sprintf("%.2g", v)
	}
}

// Report is a whole run, as committed.
type Report struct {
	Started time.Time `json:"started"`
	Binary  string    `json:"binary"`
	Pin     int       `json:"pin"`
	Options Options   `json:"options"`
	Limits  []string  `json:"limits"`
	Tables  []Table   `json:"tables"`
}

func (r Report) markdown(w io.Writer) error {
	p := &printer{w: w}

	p.printf("## Tier B, %s\n\n", r.Started.UTC().Format("2006-01-02 15:04 UTC"))
	if r.Options.Runs == 1 {
		p.printf("Each cell is one run: a %s warm-up, then %s measured.\n\n", r.Options.Warmup, r.Options.Measure)
	} else {
		p.printf("Each cell is the median of %d runs (range in brackets), each a %s warm-up, then %s measured.\n\n",
			r.Options.Runs, r.Options.Warmup, r.Options.Measure)
	}

	for _, l := range r.Limits {
		p.printf("- %s\n", l)
	}

	p.printf("\n")

	for _, t := range r.Tables {
		t.print(p)
	}

	return p.err
}

// write saves r as tierB.md and tierB.json in dir.
func (r Report) write(dir string) error {
	var md strings.Builder

	if err := r.markdown(&md); err != nil {
		return fmt.Errorf("cannot write the report: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "tierB.md"), []byte(md.String()), 0o644); err != nil { //nolint: gosec // a report
		return fmt.Errorf("cannot write the report: %w", err)
	}

	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode the report: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "tierB.json"), raw, 0o644); err != nil { //nolint: gosec // a report
		return fmt.Errorf("cannot write the report: %w", err)
	}

	return nil
}

// scenario is one table of the report: run measures it on one standing stack,
// a row per door it applies to.
type scenario struct {
	name    string
	about   string
	metrics []Metric
	run     func(ctx context.Context, b *Bench) []Row
}

// Bench is what a scenario runs against: a standing stack, a way to start a
// fresh one for figures a used process would skew, and the run's options.
type Bench struct {
	Stack *Stack
	Opts  Options
	Log   io.Writer

	// Fresh starts a new stack beside the standing one, on its own ports, for
	// a memory reading that has to start from a process nothing has used yet.
	Fresh func(ctx context.Context) (*Stack, error)
}

func (b *Bench) doors() []Door { return b.Stack.Setup.Doors }

// logf writes a progress line. A line lost to a closed terminal costs nothing,
// so its error is not kept.
func (b *Bench) logf(format string, args ...any) {
	fmt.Fprintf(b.Log, format, args...) //nolint: errcheck
}

func (b *Bench) label(door Door) string { return doorLabel(door, b.Stack.Setup.Shaping) }

func (b *Bench) has(door Door) bool { return slices.Contains(b.doors(), door) }

// cell runs one row Opts.Runs times. The first failure ends the row and is
// what it reports; the run goes on to the next row.
func (b *Bench) cell(ctx context.Context, label string, runs int, run func(context.Context) (Sample, error)) Row {
	row := Row{Label: label}

	for i := range runs {
		if err := ctx.Err(); err != nil {
			row.Err = err.Error()

			return row
		}

		settle(ctx, b.Stack.Setup, b.logf)

		s, err := run(ctx)
		if err != nil {
			b.logf("%s: run %d failed: %v\n", label, i+1, err)

			return Row{Label: label, Err: err.Error()}
		}

		b.logf("%s: run %d: %s\n", label, i+1, sampleLine(s))

		row.Samples = append(row.Samples, s)
	}

	return row
}

func sampleLine(s Sample) string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}

	slices.Sort(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+num(s[k]))
	}

	return strings.Join(parts, " ")
}

// timeWaitCeiling is how many of the run's sockets may sit in TIME_WAIT before
// a cell starts. The kernel's table holds 16,384 on the bench box; past that
// fresh connections stall, and the stall would be measured as the proxy's.
const timeWaitCeiling = 4000

// settle waits, up to 90 s, until the run's TIME_WAIT sockets are under the
// ceiling. Off Linux it cannot count them, and returns at once.
func settle(ctx context.Context, s Setup, logf func(string, ...any)) {
	for deadline := time.Now().Add(90 * time.Second); ; {
		n, err := timeWaits(s.BasePort, s.BasePort+portSpan)
		if err != nil || n < timeWaitCeiling || time.Now().After(deadline) {
			return
		}

		logf("waiting for %d TIME_WAIT sockets to clear\n", n)

		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// countTimeWaits counts the TIME_WAIT lines (state 06) of a /proc/net/tcp
// table whose local or remote port is in [lo, hi].
func countTimeWaits(table string, lo, hi int) int {
	inRange := func(addr string) bool {
		i := strings.LastIndexByte(addr, ':')
		if i < 0 {
			return false
		}

		port, err := strconv.ParseUint(addr[i+1:], 16, 16)

		return err == nil && int(port) >= lo && int(port) <= hi
	}

	n := 0

	for i, line := range strings.Split(table, "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 4 || fields[3] != "06" {
			continue
		}

		if inRange(fields[1]) || inRange(fields[2]) {
			n++
		}
	}

	return n
}

// runScenarios runs every scenario selected on b's stack and adds its rows to
// tables, which are keyed and ordered by scenario.
func runScenarios(ctx context.Context, b *Bench, selected []scenario, tables []Table) []Table {
	for _, sc := range selected {
		i := slices.IndexFunc(tables, func(t Table) bool { return t.Scenario == sc.name })
		if i < 0 {
			tables = append(tables, Table{Scenario: sc.name, About: sc.about, Metrics: sc.metrics})
			i = len(tables) - 1
		}

		tables[i].Rows = append(tables[i].Rows, sc.run(ctx, b)...)
	}

	return tables
}

// failures lists every failed row, for the exit status.
func failures(tables []Table) []string {
	var failed []string

	for _, t := range tables {
		for _, r := range t.Rows {
			if r.Err != "" {
				failed = append(failed, t.Scenario+": "+r.Label)
			}
		}
	}

	return failed
}

// allScenarios is every scenario, in report order.
func allScenarios() []scenario {
	return []scenario{
		bulkScenario(), handshakeScenario(), latencyScenario(), idleScenario(),
		contentionScenario(), limiterScenario(), slowReaderScenario(),
		capsScenario(), accountingScenario(),
	}
}

// selectScenarios picks scenarios by name from a comma-separated list, or all.
func selectScenarios(list string) ([]scenario, error) {
	all := allScenarios()
	if list == "" || list == "all" {
		return all, nil
	}

	var picked []scenario

	for name := range strings.SplitSeq(list, ",") {
		i := slices.IndexFunc(all, func(s scenario) bool { return s.name == strings.TrimSpace(name) })
		if i < 0 {
			return nil, fmt.Errorf("no scenario %q", name) //nolint: err113
		}

		picked = append(picked, all[i])
	}

	return picked, nil
}
