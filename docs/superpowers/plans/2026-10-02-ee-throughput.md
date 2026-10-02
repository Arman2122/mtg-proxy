# ee at full speed, stealthy, with ad tags — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ee downloads at close to dd's speed while keeping record-size and
idle-timing mimicry, the ad-tag (middle-proxy) leg and the ee read path
rebuilt with zero wire change, replay protection and cover-site certificate
sizing on by default — each step measured against a committed baseline.

**Architecture:** Benchmarks and byte-exact golden tests land first, so every
later change is checked against today's behaviour. The middle-proxy and TLS
read paths are rewritten behind those goldens. The doppelganger gains a
bounded buffer (both modes) and a `burst` shaping mode behind a config switch
that defaults to today's `record`. Stealth defaults change in the CLI and the
ganger.

**Tech Stack:** Go 1.26.8, testify, `golang.org/x/perf/cmd/benchstat`,
golangci-lint 2.13.2.

**Spec:** `docs/superpowers/specs/2026-10-02-ee-throughput-design.md`

## Global Constraints

- Go 1.26.8 (`go.mod`, `.mise.toml`); golangci-lint **2.13.2**: every commit
  passes `golangci-lint config verify && golangci-lint run` (0 issues) and
  `golangci-lint fmt --diff` (empty).
- Every task ends green on `go test -race ./<touched packages>/...`; Task 11
  runs `MTG_REQUIRE_BROWSER_HARNESS=1 go test -count=2 -race ./...` (26
  packages).
- **Nothing changes on the wire** except the timing of records under
  `shaping = "burst"`. Golden files are the judge.
- Frozen contracts (the Penhoon panel depends on them): release asset names,
  management API routes and fields, `/stats` feature strings, default
  `accept-modes = ["ee"]`. New config keys are optional and additive.
- History stays linear; no merge commits; no attribution lines in messages.
  Commit messages follow the repo's style: what was wrong, what changed, how
  it was verified.
- Files are written with LF line endings (Python `newline=chr(10)`; `sed -i`
  is fine).
- Bench box (Linux, 2 vCPU, shared with another project's database): work only
  in `/root/mtg-bench`, never install anything, cross-compile with
  `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c`, `chmod +x` after `scp`,
  loopback ports only, keep a run under ~10 minutes, `rm -rf /root/mtg-bench`
  at the end of each session. A test binary run there fails golden-file tests
  ("golden is missing") — run benchmarks with `-test.run '^$'`.
- Each new test is seen failing (or, for a guard written before a rewrite,
  seen passing on today's code) before the change it covers.

## Review Focus

1. **An ee client that stops reading while Telegram keeps sending** — memory
   must stop at the buffer bound, the relay must stop reading Telegram, and
   resuming must deliver every byte. Pinned in Task 7
   (`TestConnWriteBlocksAtTheBufferBound`).
2. **Middle-proxy frames split at arbitrary TCP boundaries** — 1-byte
   segments, a header split from its body, a 16-byte block straddling reads.
   Pinned in Task 2 (`TestMiddleConnDownloadSurvivesTinySegments`), re-run by
   Task 4.
3. **A kick, quota cut or shutdown while a `Write` is blocked on the full
   buffer** — it must return promptly, not hang the stream. Pinned in Task 7
   (`TestConnStopReleasesABlockedWrite`).
4. **ee upload with a non-application record or a zero-length record
   mid-stream** — skipped, and `Read` never returns `(0, nil)`. Pinned in
   Task 6 (`TestConnReadSkipsRecordsThatCarryNoData`).
5. **A secret change that brings a new cover host while streams are open** —
   that host is measured promptly; handshakes for it fall back to today's
   sizing until then; no race. Pinned in Task 10
   (`TestNewCoverHostIsMeasuredPromptly`, run under `-race`).

---

### Task 1: Tier A door benchmarks and the baseline

**Files:**
- Create: `mtglib/door_bench_test.go`, `benchmarks/README.md`,
  `benchmarks/results/2026-10-02-tierA-baseline.txt`
- Modify (helper parameters `*testing.T` → `testing.TB`, no behaviour change):
  `mtglib/proxy_entry_test.go` (`newEntryHarness`, `(*entryHarness).dialProxy`,
  `obfuscatedFrame`, `(*entryHarness).liveStream`),
  `mtglib/proxy_limits_test.go` (`govEntryCase.secret`, `.harness`,
  `.openEntry`), `mtglib/proxy_client_ips_test.go` (`connectThrough`)
- Modify: `mtglib/stream_end_test.go` — `answerBytesToEOF` uses the new
  `skipServerFlight`

**Interfaces:**
- Produces (in `door_bench_test.go`, package `mtglib`):
  `skipServerFlight(tb testing.TB, r io.Reader)` — consumes the rest of the
  three-record ee server flight after `connectThrough` read its first byte;
  `readRecordPayload(r io.Reader, n int) error` — reads TLS records until `n`
  payload bytes arrived; `writeRecords(w io.Writer, n int) error` — sends `n`
  payload bytes as 16,000-byte application records;
  `type doorCase struct{ name string; entry govEntryCase; build func(tb testing.TB, secrets map[string]Secret, limits map[string]SecretLimits) *entryHarness }`
  and `doorCases() []doorCase` returning `ee-record` (`newEntryHarness` +
  `doppelGanger.Run()`: production pacing), `ee-unpaced` (`entry.harness`),
  `dd` and `plain` (`entry.harness`). Task 8 appends `ee-burst`.

- [ ] **Step 1: Switch the harness helpers to `testing.TB`** and run
  `go test -count=1 ./mtglib/` — PASS, nothing else changed.

- [ ] **Step 2: Write the benchmarks**

  - `BenchmarkDoor/<door>/<download|upload>/conns=<1|16>` — streams set up
    outside the timer; each iteration moves 1 MiB on every stream
    concurrently; `b.SetBytes(conns << 20)`; every byte counted, mismatch is
    `b.Fatal`. ee reads records (`readRecordPayload`), ee upload sends records
    (`writeRecords`), dd/plain move raw bytes.
  - `BenchmarkDoor/dd/one-user-16-conns` vs `BenchmarkDoor/dd/16-users`
    (download) — same bytes, one secret vs sixteen.
  - `BenchmarkDoor/dd/cap-far-above` — `SpeedBytesPerSecond: 1 << 40` on the
    user: the limiter's cost when it never limits.
  - `BenchmarkDoorRoundTrip/<door>` — a 100-byte message to the fake Telegram
    and 100 bytes back per iteration; samples every round trip and reports
    `b.ReportMetric(p50µs, "p50-µs")`, `"p99-µs"`, `"p999-µs"`.
  - `BenchmarkDoorHandshake/<door>` — dial, open entry, reach the relay, end
    the stream, per iteration.
  - `BenchmarkDoorIdle/<door>` — opens 1,000 streams once, reports
    `"heap-B/conn"` (`runtime.ReadMemStats` HeapInuse after `runtime.GC()`,
    delta over the baseline) and `"goroutines/conn"`.

- [ ] **Step 3: Run locally to prove they work**

  Run: `go test -run '^$' -bench 'BenchmarkDoor' -benchtime=3x ./mtglib/`
  Expected: every sub-benchmark reports MB/s or its metrics; no `FAIL`.

- [ ] **Step 4: Write `benchmarks/README.md`** — the box rules from Global
  Constraints, and the exact commands: install
  `go install golang.org/x/perf/cmd/benchstat@latest` into a scratch `GOBIN`;
  cross-compile `mtglib` and `mtglib/internal/middleproxy` test binaries; on
  the box run each with `-test.run '^$' -test.bench . -test.benchmem
  -test.count 10 -test.benchtime 2s`, once with `GOMAXPROCS=2` and once with
  `GOMAXPROCS=1`; copy the outputs back; compare with `benchstat old new`.

- [ ] **Step 5: Take the baseline on the box** (the `mtglib` half; Task 2 adds
  the middle-proxy half) and save the raw output to
  `benchmarks/results/2026-10-02-tierA-baseline.txt` with a header naming the
  commit, `GOMAXPROCS`, and the box (2 vCPU, loopback). Remove
  `/root/mtg-bench`.

- [ ] **Step 6: Lint and commit**

```bash
git add mtglib/door_bench_test.go mtglib/proxy_entry_test.go mtglib/proxy_limits_test.go mtglib/proxy_client_ips_test.go mtglib/stream_end_test.go benchmarks/README.md benchmarks/results/2026-10-02-tierA-baseline.txt
git commit -m "bench: every door end to end, with a committed baseline"
```

### Task 2: Middle-proxy golden files and benchmark (before any rewrite)

**Files:**
- Create: `mtglib/internal/middleproxy/stream_wire_test.go`,
  `mtglib/internal/middleproxy/stream_bench_test.go`,
  `mtglib/internal/middleproxy/testdata/middle_upload_padded.golden`,
  `.../middle_upload_intermediate.golden`, `.../middle_download.golden`
- Modify: `benchmarks/results/2026-10-02-tierA-baseline.txt` (append)

**Interfaces:**
- Produces (test helpers, package `middleproxy`):
  `fixedCiphers() (proxyEnc, proxyDec, peerEnc, peerDec cipher.BlockMode)` —
  AES-256-CBC from fixed keys/IVs, mirrored so the peer decrypts what the
  proxy encrypts and vice versa; `tinyReadConn` — an `essentials.Conn` whose
  `Read` returns at most `k` bytes per call (k cycles 1, 2, 3, 16, 17).
- Golden format: lowercase hex, 64 characters per line; regenerated only when
  `MTG_UPDATE_GOLDEN=1`, the same switch `TestGoldenFakeTLSPublicPortTrace`
  uses.

- [ ] **Step 1: Write the golden tests**

  - `TestMiddleConnUploadGolden` — for `padded` true and false: a `middleConn`
    over `newFrameConn(newCBCConn(capture, proxyEnc, proxyDec), 0)` with a
    fixed connID, ad tag, client and proxy addresses; feed one client stream of
    intermediate packets (lengths 4, 16, 100, 1,024, 16,384, and one with the
    `0x80000000` quick-ack bit; the padded case adds 1–3 trailing bytes to
    each) through `Write` in chunks of 1, 5 and 4,096 bytes; the bytes written
    to `capture` must equal the golden file for that case, and must be the same
    whatever the chunk size.
  - `TestMiddleConnDownloadGolden` — a peer `frameConn` over a CBC conn with
    `peerEnc` writes, into a buffer: `RPC_PROXY_ANS` with payloads of 4,
    1,000, 16,384 and 70,000 bytes, an `RPC_SIMPLE_ACK`, then
    `RPC_CLOSE_EXT`. A `middleConn` reads it back with `dst` sizes 1, 7, 4,096
    and 65,536: the concatenated output equals the golden file for every size,
    and the read after the last byte returns `io.EOF`.
  - `TestMiddleConnDownloadSurvivesTinySegments` — the download stream above
    served through `tinyReadConn`: output identical to the golden.

- [ ] **Step 2: Generate the goldens from today's code and check they hold**

  Run: `MTG_UPDATE_GOLDEN=1 go test -run 'TestMiddleConn' ./mtglib/internal/middleproxy/`
  then without the variable: PASS, and `git status` shows the three golden
  files.

- [ ] **Step 3: Write `BenchmarkMiddleConn/<download|upload>/<16KiB|256B>`** —
  a loopback TCP pair; proxy side a `middleConn` over the CBC frame conn with
  `proxyEnc/proxyDec`, its raw conn wrapped in a read/write counter; peer side
  the mirror. `b.SetBytes(payload)`; report `"reads/MiB"` and `"writes/MiB"`
  from the counter, plus `-benchmem` allocations.

- [ ] **Step 4: Run it locally, then on the box**; append the output to the
  baseline file under its own heading; remove `/root/mtg-bench`.

- [ ] **Step 5: Lint and commit**

```bash
git add mtglib/internal/middleproxy/stream_wire_test.go mtglib/internal/middleproxy/stream_bench_test.go mtglib/internal/middleproxy/testdata benchmarks/results/2026-10-02-tierA-baseline.txt
git commit -m "test(middleproxy): pin the wire bytes both ways before touching them"
```

### Task 3: A real middle-proxy peer, and ee with an ad tag end to end

**Files:**
- Create: `mtglib/internal/middleproxy/peer.go`,
  `mtglib/proxy_adtag_ee_test.go`
- Modify: `mtglib/internal/middleproxy/manager_dial_test.go` — `fakeMiddleProxy`
  serves through `ServePeer` (its nonce/handshake/cipher code moves to
  `peer.go`)

**Interfaces:**
- Produces (exported, package `middleproxy`; documented as test support with
  no production caller, the way `doppel.Ganger.Unpace` is):

```go
type PeerRequest struct {
	ConnID  [8]byte
	Flags   uint32
	AdTag   []byte
	Payload []byte
}

// ServePeer plays the middle proxy on conn: it answers the RPC nonce and
// handshake exchange with secret, using conn's addresses for the key schedule.
func ServePeer(conn net.Conn, secret []byte) (*Peer, error)
func (p *Peer) ReadRequest() (PeerRequest, error)          // one RPC_PROXY_REQ
func (p *Peer) WriteAnswer(connID [8]byte, payload []byte) error // one RPC_PROXY_ANS
```

- Consumes: `newAdTagHarness`, `nextUpstream`, `skipServerFlight` (Task 1),
  `obfuscation.Obfuscator{Secret}.SendHandshake`, `tls.New(conn, true, true)`.

- [ ] **Step 1: Move the fake's server side into `peer.go`** and make
  `fakeMiddleProxy.serve` call it. Run
  `go test -race ./mtglib/internal/middleproxy/` — PASS
  (`TestDialProxyStreamThreadsPaddedIntermediate` still green).

- [ ] **Step 2: Write `TestFakeTLSClientWithAdTagRoundTripsThroughTheMiddleProxy`**

  An ee secret `alice` with a global ad tag (`newAdTagHarness`), the
  doppelganger unpaced and running, idle timeout one minute. The client opens
  the ee entry, skips the server flight, wraps its socket as
  `tls.New(essentials.WrapNetConn(client), true, true)` and sends the
  obfuscated frame for DC 2 with `TagPaddedIntermediate` through
  `SendHandshake`. The upstream the proxy dials is served by
  `ServePeer(middle, []byte("0123456789abcdef"))`.

  Test-local helpers: `intermediatePacket(payload []byte) []byte` (4-byte
  little-endian length, then payload) and
  `readIntermediate(t, r io.Reader) []byte` (reads one such packet).

```go
var connID [8]byte
for _, size := range []int{8, 1000, 16000} { // client -> Telegram
	payload := bytes.Repeat([]byte{0x42}, size)
	_, err := obf.Write(intermediatePacket(payload))
	require.NoError(t, err)
	req, err := peer.ReadRequest()
	require.NoError(t, err)
	assert.Equal(t, globalTag[:], req.AdTag, "every request must carry the ad tag")
	assert.Equal(t, payload, req.Payload)
	connID = req.ConnID
}
for _, size := range []int{16, 2000, 16384} { // Telegram -> client
	answer := bytes.Repeat([]byte{0x24}, size)
	require.NoError(t, peer.WriteAnswer(connID, answer))
	assert.Equal(t, answer, readIntermediate(t, obf))
}
user := userStatsJSON(t, h.proxy.stats, "alice") // the ad-tag counters are omitted while zero
assert.NotContains(t, user, "ad_tag_failed")
assert.NotContains(t, user, "ad_tag_skipped")
```

- [ ] **Step 3: Run it on today's code**

  Run: `go test -race -run 'TestFakeTLSClientWithAdTag' -v ./mtglib/`
  Expected: PASS — this is the guard the rewrites in Tasks 4–5 must keep green.

- [ ] **Step 4: Lint and commit**

```bash
git add mtglib/internal/middleproxy/peer.go mtglib/internal/middleproxy/manager_dial_test.go mtglib/proxy_adtag_ee_test.go
git commit -m "test(adtag): an ee client through a real middle-proxy exchange, both ways"
```

### Task 4: Middle-proxy download at full speed

**Files:**
- Modify: `mtglib/internal/middleproxy/frame.go` (`cbcConn`, `frameConn.readPacket`),
  `mtglib/internal/middleproxy/stream.go` (`middleConn.Read`, `frameIntermediate`)

**Interfaces:**
- `newCBCConn(raw io.ReadWriter, enc, dec cipher.BlockMode) *cbcConn` keeps its
  signature; it now owns `r *bufio.Reader` of `cbcReadBuffer = 64 << 10` over
  `raw` (writes still go to `raw`).
- New: `func (c *cbcConn) buffered() int` — decrypted pending bytes plus
  undecrypted bytes in `r`; `func (f *frameConn) nextFrameBuffered() bool` —
  true only when the next whole frame (after any `0x04000000` padding words)
  is already buffered, decided by decrypting at most its first block into the
  pending area (CBC chaining makes decrypting ahead safe).
- `readPacket` returns a slice of a per-`frameConn` body buffer, valid until
  the next `readPacket`.

- [ ] **Step 1: Write the efficiency test** —
  `TestMiddleConnDownloadReadsInBulk`: download 1 MiB of 16 KiB answers
  through a raw conn that counts `Read` calls; assert fewer than 64 reads
  (today: over 65,000) and `testing.AllocsPerRun` per 16 KiB packet ≤ 1.
- [ ] **Step 2: Run it** — FAIL on the read count.
- [ ] **Step 3: Implement** — `cbcConn.Read(p)`: serve pending plaintext
  first; then, if `len(p) >= 16`, read the largest whole-block prefix that
  `r` can give without a second blocking read into `p` and `CryptBlocks` it
  in place; a read shorter than a block decrypts one block into a fixed
  `[16]byte` and serves from it. `middleConn.Read(dst)`: copy the 4-byte
  intermediate length and the payload straight from the frame body (no
  `frameIntermediate` allocation, no `outbuf` append), and while `dst` has
  room and `nextFrameBuffered()`, take the next packet in the same call.
  `RPC_SIMPLE_ACK` keeps its verbatim, length-less forwarding.
- [ ] **Step 4: Run** `go test -race ./mtglib/internal/middleproxy/ ./mtglib/`
  — PASS: the efficiency test, all three goldens, the tiny-segment test, and
  `TestFakeTLSClientWithAdTag…`.
- [ ] **Step 5: Bench on the box** (`BenchmarkMiddleConn/download`), compare
  with `benchstat` against the baseline, put the comparison in the commit
  message.
- [ ] **Step 6: Lint and commit** — `perf(middleproxy): read and decrypt the download in bulk`.

### Task 5: Middle-proxy upload at full speed

**Files:**
- Modify: `mtglib/internal/middleproxy/frame.go` (`frameConn.writePacket`,
  `cbcConn.Write`), `mtglib/internal/middleproxy/stream.go`
  (`middleConn.Write`, `buildProxyReq`, `encodeIPPort`)

**Interfaces:**
- New: `func (f *frameConn) appendFrame(dst []byte, parts ...[]byte) []byte` —
  appends one plaintext frame (length, sequence number, `parts` in order,
  CRC32 via `crc32.Update`, padding words) and advances the write sequence
  number; `func (c *cbcConn) writeEncrypted(buf []byte) error` — encrypts
  `buf` in place (a whole number of blocks) and writes it with one call.
  `writePacket` becomes `appendFrame` + `writeEncrypted` (or a plain write
  for the pre-CBC nonce frame), so the handshake path shares the code.
- `middleConn` keeps two reusable buffers: the client byte stream (compacted in
  place as packets are consumed, never re-sliced forward forever) and the
  outgoing frames. The fixed RPC header prefix (tag, flags, connID, both
  encoded addresses, extra size, proxy tag, ad tag, alignment) is built once
  per conn; only the flags word varies per packet (quick-ack, encrypted).

- [ ] **Step 1: Write the efficiency test** — `TestMiddleConnUploadWritesOnce`:
  one `Write` carrying eight complete 1 KiB packets makes exactly one write on
  the raw conn, and `AllocsPerRun` per packet is 0 in steady state.
- [ ] **Step 2: Run it** — FAIL (eight writes, ~10 allocations per packet).
- [ ] **Step 3: Implement** as in Interfaces. Frames for every complete packet
  in one `Write` are appended to the outgoing buffer and encrypted in one
  `CryptBlocks` call — identical ciphertext to encrypting them one by one,
  since CBC chains across them.
- [ ] **Step 4: Run** `go test -race ./mtglib/internal/middleproxy/ ./mtglib/`
  — PASS, upload goldens byte-identical, `TestFakeTLSClientWithAdTag…` green.
- [ ] **Step 5: Bench on the box** (`BenchmarkMiddleConn/upload`), `benchstat`
  into the commit message.
- [ ] **Step 6: Lint and commit** — `perf(middleproxy): build each upload frame in place and send a chunk in one write`.

### Task 6: ee read path

**Files:**
- Modify: `mtglib/internal/tls/conn.go`
- Test: `mtglib/internal/tls/conn_test.go`

**Interfaces:**
- `New(conn essentials.Conn, read, write bool) Conn` unchanged. New constant
  `ReadBufferSize = 64 << 10` for the buffered reader (`DefaultBufferSize`
  stays 4096; the doppelganger uses it). `connPayload` drops `readBuf` and
  keeps `remaining int` — payload bytes left in the current application-data
  record.
- `ReadRecord` stays as it is (tests and other callers use it).

- [ ] **Step 1: Write the tests**
  - `TestConnReadSpansRecords` — two buffered application records of 100 and
    200 bytes, `Read` into 1,024 bytes returns 300 in one call.
  - `TestConnReadOneByteAtATime` — 3 records read with a 1-byte buffer
    reproduce the payload exactly.
  - `TestConnReadSkipsRecordsThatCarryNoData` — a change-cipher-spec record and
    a zero-length application record between two data records: the payload is
    exact and no `Read` returns `(0, nil)`.
  - `TestConnReadRejectsWrongVersion` — a record with version `03 01` errors
    as `ReadRecord` does today.
  - `TestConnReadAllocatesNothing` — `testing.AllocsPerRun` over a 16 KiB
    record read is 0.
- [ ] **Step 2: Run them** — `SpansRecords` and `AllocatesNothing` FAIL.
- [ ] **Step 3: Implement** — parse the 5-byte header from the buffered reader
  (version check as `ReadRecord`); for application data copy
  `min(len(p), remaining)` straight from the reader into `p`; keep filling
  `p` from following records while their headers are already buffered;
  discard other records' payloads with `Discard`.
- [ ] **Step 4: Run** `go test -race ./mtglib/internal/tls/ ./mtglib/` — PASS,
  including `TestGoldenFakeTLSPublicPortTrace` and `BenchmarkDoor` ee upload
  rows still counting every byte.
- [ ] **Step 5: Bench the ee upload rows on the box**, `benchstat` into the
  message.
- [ ] **Step 6: Lint and commit** — `perf(tls): read records straight into the caller's buffer, several per read`.

### Task 7: The doppelganger's buffer gets a bound

**Files:**
- Modify: `mtglib/internal/doppel/conn.go`
- Test: `mtglib/internal/doppel/conn_buffer_test.go`

**Interfaces:**
- New constant `MaxBuffered = 256 << 10`. `Write` blocks while the queue holds
  at least `MaxBuffered` bytes, until the writer drains it, `CloseWrite` or
  `Stop` is called, or the conn's context ends; then it appends all of `p`
  (so the queue peaks at `MaxBuffered + len(p)`). The writer broadcasts on
  the conn's condition variable after every read from the queue;
  `NewConn` registers `context.AfterFunc(ctx, …)` that broadcasts, so a
  cancelled context always wakes a blocked `Write`.

- [ ] **Step 1: Write the tests**
  - `TestConnWriteBlocksAtTheBufferBound` — paced fast (`Stats{k: 2, lambda: 1}`),
    the far end not reading: a goroutine writes 4 MiB in 16 KiB pieces; after
    500 ms the queue is ≤ `MaxBuffered + 16<<10` and the goroutine has not
    finished; the far end then reads TLS records to EOF after `CloseWrite`:
    exactly 4 MiB of payload.
  - `TestConnStopReleasesABlockedWrite` — `Write` blocked on the bound;
    `Stop()` from another goroutine; `Write` returns an error within 1 s.
  - `TestConnCancelReleasesABlockedWrite` — same, cancelling the conn's
    context instead of `Stop`.
- [ ] **Step 2: Run them** — `BlocksAtTheBufferBound` FAILS (the queue grows
  to 4 MiB).
- [ ] **Step 3: Implement** as in Interfaces.
- [ ] **Step 4: Run** `go test -race ./mtglib/internal/doppel/ ./mtglib/` —
  PASS, including `TestStreamEndDeliversTheWholeAnswer`,
  `TestSpeedLimitAppliesThroughTheProxy` (`-count=20`) and the door
  benchmarks at `-benchtime=3x`.
- [ ] **Step 5: Lint and commit** — `fix(doppel): bound the write queue so a slow client stops the relay, not the heap`.

### Task 8: Burst shaping behind `shaping`

**Files:**
- Modify: `mtglib/internal/doppel/conn.go`, `mtglib/internal/doppel/ganger.go`,
  `mtglib/proxy.go`, `mtglib/proxy_opts.go`, `internal/config/parse.go`,
  `internal/config/config.go`, `internal/cli/run_proxy.go`,
  `example.config.toml`, `docs/wiki/Configuration.md`,
  `mtglib/proxy_entry_test.go` (harness `NewGanger` call),
  `mtglib/door_bench_test.go` (`ee-burst` row), `mtglib/stream_end_test.go`
  (`ee-burst` case), doppel tests calling `NewConn`/`NewGanger`
- Create: `internal/config/type_doppel_shaping.go` (+ `_test.go`),
  `mtglib/internal/doppel/conn_burst_test.go`

**Interfaces:**
- `doppel`: `type Shaping uint8`; `const ( ShapingRecord Shaping = iota; ShapingBurst )`;
  `func ParseShaping(s string) (Shaping, error)` — `""` and `"record"` →
  record, `"burst"` → burst, anything else an error naming both values;
  `func NewConn(ctx context.Context, conn essentials.Conn, stats Stats, shaping Shaping) Conn`;
  `func NewGanger(ctx, network, logger, scoutEach, scoutRepeats, urls, drs, shaping Shaping) *Ganger`;
  `const BurstWriteMax = 64 << 10`. Idle is `TLSRecordSizeResetAfter` (1 s).
- `mtglib.ProxyOpts.DoppelGangerShaping string`; `opts.valid()` rejects a
  value `ParseShaping` refuses.
- Config: TOML `[defense.doppelganger] shaping`, struct field
  `Shaping TypeDoppelShaping \`json:"shaping"\``; type modelled on
  `TypePreferIP` with constants `TypeDoppelShapingRecord = "record"`,
  `TypeDoppelShapingBurst = "burst"`; default `"record"`.

Burst write loop, per wake (the algorithm the tests do not determine):

```text
wait until the queue has data (or closing/done)
if lastWrite is zero or now - lastWrite >= TLSRecordSizeResetAfter:
    wait one stats.Delay() (select on the timer and ctx)
batch = empty
repeat while the queue has data:
    size = pendingSize, or stats.Size() if none is pending   // drawn once per record
    if len(batch) + SizeHeader + min(size, queued) > BurstWriteMax and batch not empty:
        keep size as pendingSize for the next batch; stop
    append one record of min(size, queued) bytes from the queue to batch
write batch with one call; lastWrite = now; broadcast
```

Record sizes are therefore exactly what `Stats.Size()` draws (DRS ramp and
idle reset included); only how many share a system call changes.

- [ ] **Step 1: Write the tests**
  - `TestBurstSendsRecordsBackToBack` — `Stats{k: 1, lambda: 60_000}` (a
    minute per wait): writing 1 MiB, then `CloseWrite`, delivers all of it in
    under 2 s, every record 16,379 bytes except the last.
  - `TestBurstWaitsOnceAfterIdle` — `Stats{k: 50, lambda: 300}` (≈300 ms,
    nearly constant): the first write's first record arrives ≥ 250 ms after
    it; a second write 200 ms later arrives within 50 ms; a third write after
    1.2 s of quiet arrives ≥ 250 ms after it.
  - `TestBurstKeepsDRSRecordSizes` — `drs = true`, unpaced: the first 40
    records are 1,351–1,450 bytes, the next 20 are 3,997–4,096, then 16,379.
  - `TestRecordShapingIsUnchanged` — `ShapingRecord` with
    `Stats{k: 50, lambda: 100}`: four records of a 64 KiB write take ≥ 350 ms.
  - Config: `TestTypeDoppelShaping` (valid values, case-insensitive, error
    names both), and a parse test that `[defense.doppelganger] shaping =
    "burst"` reaches `Config`.
  - `TestStreamEndDeliversTheWholeAnswer` gains an `ee-burst` case.
- [ ] **Step 2: Run them** — FAIL (no `Shaping`, compile error).
- [ ] **Step 3: Implement**; wire `run_proxy.go` →
  `ProxyOpts.DoppelGangerShaping` → `NewProxy` → `NewGanger`; document the
  key in `example.config.toml` and `docs/wiki/Configuration.md` (default
  `record`, what `burst` changes on the wire, that it is being canaried).
- [ ] **Step 4: Run** `go test -race ./mtglib/... ./internal/...` — PASS.
- [ ] **Step 5: Bench `ee-burst` on the box** against `ee-record`, `ee-unpaced`
  and `dd`; the spec's bar is `ee-burst` download on one connection within
  ~20% of `dd`. `benchstat` into the message.
- [ ] **Step 6: Lint and commit** — `feat(doppel): burst shaping, behind [defense.doppelganger] shaping`.

### Task 9: Replay protection on by default

**Files:**
- Modify: `internal/cli/run_proxy.go:106`, `example.config.toml`
  (`[defense.anti-replay]` comment), `docs/wiki/Security.md`,
  `docs/wiki/Configuration.md`
- Test: `internal/cli/anti_replay_default_test.go`

- [ ] **Step 1: Write the tests**
  - `TestAntiReplayIsOnWithoutConfiguration` — `config.Parse` of a config
    with `bind-to` and one secret and no `[defense]`;
    `makeAntiReplayCache(conf)` returns a cache for which
    `SeenBefore(x)` is false, then true for the same `x`.
  - `TestAntiReplayCanStillBeTurnedOff` — `[defense.anti-replay] enabled =
    false` → `SeenBefore(x)` is false both times.
- [ ] **Step 2: Run them** — the first FAILS (no-op cache).
- [ ] **Step 3: Implement** — `Enabled.Get(true)`. Docs state the default and
  its cost: 1 MiB per process; at the default error rate about one genuine
  connection attempt in a thousand is fronted and retried by the client.
- [ ] **Step 4: Run** `go test -race ./internal/cli/ ./mtglib/` — PASS.
- [ ] **Step 5: Lint and commit** — `fix(defense): replay protection on unless turned off` (the message says the panel never wrote `[defense.anti-replay]`, so its proxies ran without it).

### Task 10: Fake certificate sized per cover host, out of the box

**Files:**
- Modify: `mtglib/internal/doppel/ganger.go`, `mtglib/internal/doppel/scout.go`,
  `mtglib/proxy.go` (`NewProxy`, before `doppelGanger.Run()`),
  `mtglib/proxy_secrets.go` (`swapSecretConfigLocked`), `mtglib/proxy_entry.go:75`
- Create: `mtglib/internal/doppel/cover_test.go`,
  `mtglib/cover_hosts_test.go`

**Interfaces:**
- `doppel`: `type CoverHost struct{ Host, Addr string }`;
  `func (g *Ganger) SetCoverHosts(hosts []CoverHost)` — safe at any time
  (mutex-guarded list plus a capacity-1 notify channel the run loop selects
  on); `func (g *Ganger) CoverHosts() []CoverHost` — a copy;
  `func (g *Ganger) NoiseParamsFor(host string) NoiseParams` — the host's
  calibration, else the global `NoiseParams()`, else the zero value (today's
  fallback); `func (s Scout) LearnCover(ctx context.Context, h CoverHost) (ScoutResult, error)`
  — `GET https://<Host>/`, dialling `Addr` instead of what DNS says, SNI and
  `Host` header from `Host`. The size statistic is today's
  `updateNoiseParams` logic, extracted as `noiseFromSizes(sizes []int) (NoiseParams, bool)`.
- `mtglib`: `func (p *Proxy) coverHosts(set *secretSet) []doppel.CoverHost` —
  distinct `Host` of the set's ee secrets in name order, `Addr` from
  `p.domainFrontingAddressForHost(host)`, skipping an empty address.
- Rule: with `[defense.doppelganger] urls` configured, behaviour is exactly
  today's (cover hosts are recorded but not scouted, `NoiseParamsFor` returns
  the global value). With none, raids scout each cover host
  `repeats_per_raid` times; their durations feed the global delay statistics
  and their certificate sizes a per-host `NoiseParams`. A host never measured
  is raided as soon as `SetCoverHosts` names it; afterwards on the normal
  `raid_each` cadence.

- [ ] **Step 1: Write the doppel tests** (two `httptest` TLS servers whose
  certificate chains differ in size — one certificate with a few hundred
  extra SANs — on the test network that skips verification)
  - `TestCoverHostsAreMeasuredSeparately` — `SetCoverHosts(a, b)`, no URLs:
    within 5 s `NoiseParamsFor("a.test").Mean` is within
    `NoiseParamsFor("a.test").Jitter` of server A's measured chain size, the
    same for B, and the two means differ by more than both jitters.
  - `TestNewCoverHostIsMeasuredPromptly` — start with `a` only, add `b` later
    with `raid_each` set to one hour: `b` is calibrated within 5 s; meanwhile
    `NoiseParamsFor("b.test")` returns the fallback, under `-race`.
  - `TestConfiguredURLsKeepTodaysBehaviour` — with URLs set,
    `NoiseParamsFor(anything)` equals `NoiseParams()` and no request reaches
    the cover servers.
- [ ] **Step 2: Write `TestCoverHostsFollowTheSecrets`** (package `mtglib`) —
  a proxy with secrets naming `a.example` and `b.example` reports both in
  `doppelGanger.CoverHosts()` with their fronting addresses; after a secret
  swap replacing `b` with `c` it reports `a` and `c`; with
  `domainFrontingHost` set, every `Addr` uses it.
- [ ] **Step 3: Run them** — FAIL (compile errors).
- [ ] **Step 4: Implement** as in Interfaces; `proxy_entry.go` uses
  `p.doppelGanger.NoiseParamsFor(result.MatchedHost)`.
- [ ] **Step 5: Run** `go test -race ./mtglib/... ` — PASS, including the
  FakeTLS goldens.
- [ ] **Step 6: Lint and commit** — `feat(doppel): size the fake certificate from each cover host, without configured URLs`.

### Task 11: Full gate, the before/after report, and the notes

**Files:**
- Create: `benchmarks/results/2026-10-02-tierA-after.txt`,
  `benchmarks/results/2026-10-02-ee-throughput-report.md`
- Modify: `docs/wiki/Security.md` (what ee defends against now, and the open
  key-share question), `docs/wiki/Configuration.md` if Tasks 8–9 left gaps

- [ ] **Step 1: Full gate** — `MTG_REQUIRE_BROWSER_HARNESS=1 go test -count=2 -race ./...`
  (26 packages, 0 failures); `golangci-lint config verify && golangci-lint run`
  (0 issues); `golangci-lint fmt --diff` (empty);
  `govulncheck ./...` (nothing reachable).
- [ ] **Step 2: On the box** — run every new test package's tests that do not
  need golden files (`-test.run` excluding `Golden`), then Tier A in full,
  `GOMAXPROCS=2` and `1`, `-count 10`; save as
  `2026-10-02-tierA-after.txt`; remove `/root/mtg-bench`.
- [ ] **Step 3: Write the report** — `benchstat baseline after` per door; the
  spec's "Done when" list item by item, each with its number or test; the
  limits (2 vCPU, loopback, Tier B and WEB not yet measured).
- [ ] **Step 4: Commit** — `bench: ee throughput, before and after`.

### Task 12: Release and canary (each step needs the user's go-ahead)

- [ ] Push `main`. Tag a release with hand-written GitHub release notes (what
  changed, the `shaping` key and its canary status, the replay-protection
  default and its cost, the report's headline numbers).
- [ ] Deploy to the live server with `[defense.doppelganger] shaping = "burst"`
  after recording a week of `/stats` (per-user connections, bytes,
  handshakes, frontings) as the comparison.
- [ ] After 3–7 days compare; if nothing dropped, a later release makes
  `burst` the default (Task 8's type default and the docs change; nothing
  else).
