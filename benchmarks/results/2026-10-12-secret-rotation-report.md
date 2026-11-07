# Secret rotation with an overlap period: what it costs

Measured 2026-10-12 on the bench box (2 vCPU Skylake, no SHA-NI, a shared database host, loopback only), same-session A/B,
old and new binaries alternated ten times. The tables and the exact protocol are in
[2026-10-12-secret-rotation-ab.txt](2026-10-12-secret-rotation-ab.txt), the raw output in
[2026-10-12-secret-rotation-ab-raw.txt](2026-10-12-secret-rotation-ab-raw.txt).

*Old* is the tree just before the first code change of this piece (commit `8577930`); *new* is its final code (`9d126e3`).

## The short answer

- **A deployment that never rotates pays nothing measurable.** All 21 existing handshake rows (ee and dd, 1 to 5,000 secrets,
  first and last in the list, hinted and not) show no significant change in time (every p above 0.1; the largest single-row
  movement is +5.0%, inside that row's own +-12% noise). Allocations per connection are equal on 20 rows and one allocation fewer
  in about 15,170 on the 21st. Bytes per connection grow by 0.03% to 0.38% on ten rows: about 50 to 60 bytes, the fields the matched
  key travels in.
- **A client on a previous key costs what its position in the list says.** The door tries every primary and then the retiring
  entries, so a client on a retiring key is the "last" row at N+R candidates. Against a same-binary control (the existing `last`
  row at N+R, no retiring entries) the measured rows are within noise: 5,000 secrets with 100 retiring keys, ee 16.1 ms against
  15.9 ms, dd 5.69 ms against 5.77 ms. A returning client (the door remembers which names an address used) never scans: 0.96 to
  0.98 ms at every N and R, the same as a returning client on a primary.
- **The rest scales with the number of entries.** Building the set for 5,000 secrets takes 12.1 ms with no retiring entries,
  12.3 ms with 100 and 25.0 ms with 4,096 (the cap). Judging 10,000 open streams after a swap takes 0.51 ms when nothing about
  rotation changed (the held-key fast path), 0.61 ms during an overlap, 2.5 ms when every secret rotates and 7.7 ms for the swap
  that ends an overlap (it also collects and cancels all 10,000).

## What was measured, and how far to trust it

- Existing rows, scan budget, the no-retiring set build and bulk throughput: ten alternating iterations per side (five for
  bulk), `benchstat` at its defaults. Same session, same box, `-test.cpu 2`, TIME_WAIT under 200 between runs.
- The new rows ran on the new binary only, three passes: `benchstat` gives no interval for three samples, so those figures are
  indicative. The control rows are what make them readable.
- A first full run the same afternoon, without `-test.benchmem`, agreed on every existing row.
- The box is shared and its load swings; a row carries +-4% to +-14% of noise. The geomean of the existing rows read -0.35% in the
  first run and +1.20% in the second: that is the noise, not a trend.
- Loopback runs do not exercise the network card, and 4 to 8 core scaling is unmeasured: the box has two cores.

## The Unix-only code paths

The command's file handling (owner, group and mode, the 0600 temporary file, symlinks, hard links, EBUSY/EXDEV and read-only
mounts, SIGPIPE, signals) cannot run on the Windows machine the work was done on, so it ran here: the cross-compiled test
binaries for `internal/rotation` (139 passes) and `internal/cli` (342 passes as root, 339 as an emulated non-root user: a user
namespace with uid 1000 and no capabilities, because `/root` is mode 0700) with no failures, and six deliberately broken builds
each failed the test that guards the behaviour. The real linux binary was then run against a running proxy: `rotate-secret
--overlap 1h --reload` (one line on stdout, the read-back saying the proxy serves the file as written, `retiring_keys` 1 in
`GET /secrets/default`), a second rotation inside the overlap (2 keys, the longer `until` kept), `--end-overlap --reload`, a closed
stdout, an unreachable management API (refused before anything is written), and real SIGINT, SIGTERM and SIGHUP while the command
waited on a management API that never answered (each ends the wait at once, exit 1, nothing written, no leftovers).

## What was not measured

Signals on macOS, a Docker single-file bind mount after a rename, NFS, a real second user account on the box, Windows
behaviour beyond the cross-checks done on the development machine (EFS, an elevated run, SMB/ReFS/FAT volumes).
