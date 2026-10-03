# WEB relay speed — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut the WEB relay's CPU per byte, memory per idle connection and
setup cost, without changing its structure or its wire, and fix the
deleted-session defect.

**Architecture:**
- **Upload:** a client message costs one allocation. The unmask works on
  64-bit words, and DATA payloads are slices of the message.
- **Download:** reads land in pooled, right-sized buffers that the DATA
  frame carries as-is. Each batch goes out as one vectored write, and the
  buffers return to the pool after it.
- **Sessions:** tombstones grow on demand, a cancelled session closes its
  WebSocket, and the bridge page is written from parts.

**Tech Stack:** Go 1.26.8, standard library only (`net.Buffers`,
`sync.Pool`, `context.AfterFunc`), testify, benchstat, golangci-lint
2.13.2.

**Spec:** `docs/superpowers/specs/2026-10-03-web-relay-speed-design.md`

## Global Constraints

- **The wire does not change.** Every byte the relay sends and accepts
  stays as it is, proven against today's `EncodeBatch` / `DecodeBatch`.
- **The structure stays:**
  - the relay is a separate process;
  - each stream keeps two goroutines;
  - credit returns only after the backend write;
  - the outbox, its budgets and its batch limits are unchanged;
  - every protocol check in `ws` and `frame` stays.
- **No new dependencies, no new configuration.**
- **Buffer ownership:**
  - a message buffer belongs to the frames sliced from it until the last
    one is written;
  - a pooled buffer belongs to its frame until the write loop has written
    it, and is never touched after release;
  - a batch dropped at shutdown is left to the garbage collector.
- **Measure, then add:** no reference-counted pool for upload buffers in
  this plan.
- **Every commit passes:**
  - `golangci-lint config verify && golangci-lint run` with 0 issues;
  - `golangci-lint fmt --diff` empty;
  - `go test -race` over the touched packages.
- **Bench box rules:**
  - work in `/root/mtg-bench` only, and remove it at the end;
  - install nothing;
  - loopback ports 47000–47099;
  - TIME_WAIT under 200 between runs;
  - each run bounded to about 15 minutes.
- **Repo style:**
  - LF line endings, linear history, no attribution lines;
  - commit messages say what was wrong, what changed and how it was
    verified.

## Review Focus

1. **A fragmented client message** (several WebSocket frames, different
   masks, a ping between them) assembles byte-exact in the new read path,
   and the message limit still holds across fragments. Pinned in Task 2,
   `TestAFragmentedMessageIsAssembledInOneBuffer`.
2. **A pooled buffer used after release.** If a DATA payload is released
   while another stream or a later batch still reads it, the client gets
   garbage. Pinned in Task 4:
   - released buffers are poisoned in tests;
   - `TestStreamsClosingMidTransferNeverCorruptOthers` runs under `-race`.
3. **Credit drift across buffer sizes.** A stream toggling between 4 KiB and
   64 KiB reads must spend and refund exactly, or it stalls. Pinned in
   Task 4, `TestABurstyBackendIsRelayedExactly`.
4. **A failed vectored write** must end the session, not continue with a
   half-sent message, and must not release buffers twice. Pinned in Task 4,
   `TestAFailedCarrierWriteEndsTheSession`.
5. **`ws.Conn.Read` must hand out a fresh buffer every time.** Aliased
   payloads depend on it. Pinned in Task 2,
   `TestReadReturnsAFreshBufferEachTime`.

---

### Task 1: the before figures

**Files:**
- Modify: `internal/webrelay/chain_bench_test.go`. In
  `BenchmarkDoorHandshake`, the client's `testclient.WebOptions` gains
  `ReadBufferSize: 4 << 10`, so the allocation it reports is the relay's.
- Create:
  - `benchmarks/results/2026-10-03-web-speed-before.txt` (Tier A);
  - `benchmarks/results/2026-10-03-web-speed-before-tierB.md`.

- [ ] **Step 1: Change the handshake client's buffer** and run it once.
  Run: `go test -run '^$' -bench 'BenchmarkDoorHandshake/web' -benchtime 200x -benchmem ./internal/webrelay/`
  Expected: B/op falls from ~650 KB to under 450 KB. The test client's
  256 KiB read buffer is gone; the relay is unchanged.
- [ ] **Step 2: Run the before figures on the box.** Use this commit's
  binaries:
  - Tier A:
    `webrelay.test -test.run '^$' -test.bench BenchmarkDoor -test.benchmem -test.count 6 -test.benchtime 1s`,
    at `GOMAXPROCS` 2 then 1.
  - Tier B:
    `taskset -c 1 ./mtgbench -bin ./mtg-proxy -pin 0 -dir /root/mtg-bench/work -out tierB -scenarios bulk,handshake,latency,idle -doors dd,web`.

  Headers as in `2026-10-03-tierA-web-and-additions.txt` and
  `2026-10-03-tierB.md`. Expected: every row passes. Leave the box
  directory for Task 6.
- [ ] **Step 3: Commit.**
  `bench: the WEB relay before -- a handshake client that measures the relay`.

### Task 2: one allocation per message, and a word-wise unmask

**Files:**
- Modify: `internal/webrelay/ws/ws.go`. Change `Conn.Read` and `unmask`.
- Test: `internal/webrelay/ws/ws_test.go`.

**Interfaces:**
- Produces: `(*Conn).Read() ([]byte, error)`, unchanged in signature. Its
  contract tightens: every call returns a newly allocated slice that is
  never written again.

- [ ] **Step 1: Write the failing tests.**
  - `TestUnmaskMatchesTheDefinition`. For every length 0..300, every offset
    0..3 and 64 random masks, `unmask` equals the byte-at-a-time
    definition `p[i] ^= mask[(i+offset)%4]`.
  - `FuzzUnmask`, the same comparison over fuzzed payload, mask and offset.
  - `TestASingleFrameMessageIsOneAllocation`.
    - Setup: a `Conn` over a `bufio.Reader` holding 100 masked 64 KiB binary
      frames, with a conn whose deadline setters return nil.
    - Assert: `testing.AllocsPerRun(100, func(){ c.Read() }) == 1`.
  - `TestAFragmentedMessageIsAssembledInOneBuffer`.
    - Setup: three fragments of 10, 70,000 and 5 bytes under three masks,
      with a ping between the second and third.
    - Assert: `Read` returns the 70,015 bytes exactly, and a pong was
      written.
    - Assert: the same fragments with `MaxMessage` 70,000 return
      `ErrMessageTooBig`.
  - `TestReadReturnsAFreshBufferEachTime`. Two reads of equal-length
    messages return slices whose backing arrays differ, and the first is
    unchanged after the second read.
- [ ] **Step 2: Run them red.**
  Run: `go test -run 'Unmask|OneAllocation|Fragmented|FreshBuffer' ./internal/webrelay/ws/`
  Expected:
  - `TestASingleFrameMessageIsOneAllocation` fails (2 allocations today);
  - the unmask equivalence passes (behaviour is unchanged; it is the
    guard);
  - the fragmented and fresh-buffer tests pass today and stay as guards.
- [ ] **Step 3: Implement.**
  - **`Read`:** a single-frame message reads straight into
    `make([]byte, header.length)`. A continuation grows the message once
    (`slices.Grow`) and reads into its tail. Nothing is appended from a
    temporary.
  - **`unmask`:**
    - rotate the mask by `offset`;
    - XOR eight bytes at a time with the mask repeated into a
      little-endian `uint64`;
    - finish the tail byte by byte with the rotated mask.
- [ ] **Step 4: Run the package.**
  Run: `go test -race ./internal/webrelay/ws/` and `go test -fuzz FuzzUnmask -fuzztime 30s ./internal/webrelay/ws/`
  Expected: PASS.
- [ ] **Step 5: Commit.**
  `perf(ws): one allocation per client message, and unmask a word at a time`.

### Task 3: frames that slice and vectors that do not copy

**Files:**
- Modify:
  - `internal/webrelay/frame/decode.go`, `internal/webrelay/frame/encode.go`;
  - `internal/webrelay/session.go`: `readLoop` uses the aliasing decoder.
- Test: `internal/webrelay/frame/frame_test.go`.

**Interfaces:**
- Produces:
  - `func (l Limits) DecodeBatchAliased(b []byte, dir Direction) ([]Frame, error)`
    has the same validation and errors as `DecodeBatch`. Each non-empty
    payload is `b[i:j]`, not a copy, so the caller must not reuse `b`.
  - `func (l Limits) BatchVectors(vecs [][]byte, headers []byte, frames []Frame, dir Direction) ([][]byte, []byte, error)`
    has the same validation and errors as `EncodeBatch`. It appends to
    `vecs`, for each frame, its 8-byte header (a slice of `headers`, grown
    once to `len(frames)*HeaderSize`) and its payload when non-empty. It
    returns `vecs` and `headers` for reuse.

- [ ] **Step 1: Write the failing tests.**
  - `TestTheAliasedDecoderSlicesTheMessage`, for a batch of OPEN, DATA
    (1 byte and 64 KiB), WINDOW and CLOSE frames:
    - its frames equal `DecodeBatch`'s;
    - each DATA payload's first byte is the same memory as the message's,
      `&p[0] == &b[off]`.
  - `TestTheAliasedDecoderRefusesWhatTheCopyingOneRefuses`: for every
    malformed batch already in the decode tests, both return the same
    error (`errors.Is`) and no frames.
  - `TestBatchVectorsAreTheEncodedBatch`. For batches of 1, 2, 17 and
    `MaxFramesPerBatch` frames, empty payloads included, in both
    directions: `bytes.Join(vecs, nil)` equals `EncodeBatch(nil, frames, dir)`.
  - `TestBatchVectorsRefuseWhatEncodeBatchRefuses`. Too many frames, over
    the byte budget, and an invalid frame each give the same error as
    `EncodeBatch`.
- [ ] **Step 2: Run them red.**
  Run: `go test -run 'Aliased|BatchVectors' ./internal/webrelay/frame/`
  Expected: FAIL to compile. Neither function exists.
- [ ] **Step 3: Implement both.** `DecodeBatch` and `DecodeBatchAliased`
  share one loop with a copy flag. `BatchVectors` shares `EncodeBatch`'s
  checks. Then switch `session.readLoop` to `DecodeBatchAliased`. The
  message `ws.Conn.Read` returns is fresh per call (Task 2).
- [ ] **Step 4: Run the packages.**
  Run: `go test -race ./internal/webrelay/frame/ ./internal/webrelay/`
  Expected: PASS. The relay–proxy chain tests check every byte end to end.
- [ ] **Step 5: Commit.**
  `perf(frame): decode by slicing the message, and batches as write vectors`.

### Task 4: pooled reads and one vectored write per message

**Files:**
- Create: `internal/webrelay/readbuf.go`, the read-buffer pools and the
  adaptive size policy.
- Modify:
  - `internal/webrelay/ws/ws.go`: add `WriteBuffers`;
  - `internal/webrelay/session.go`: the `carrier` interface and
    `writeLoop`;
  - `internal/webrelay/stream.go`: `pump`.
- Test:
  - `internal/webrelay/readbuf_test.go`, `internal/webrelay/ws/ws_test.go`;
  - `internal/webrelay/session_test.go` (`testCarrier` implements
    `WriteBuffers`);
  - `internal/webrelay/relay_proxy_chain_test.go`.

**Interfaces:**
- Consumes: `BatchVectors` from Task 3.
- Produces:
  - `func (c *ws.Conn) WriteBuffers(bufs [][]byte) error` sends one binary
    message whose payload is the concatenation of `bufs`, as one
    `net.Buffers` write. Same deadline and locking as `Write`.
  - In `readbuf.go`:
    - `const smallRead = 4 << 10`;
    - `largeRead = frame.MaxRelayDataChunk`;
    - `func getReadBuffer(large bool) []byte`;
    - `func releaseReadBuffer(b []byte)`, which pools by `cap(b)` and
      ignores any other capacity;
    - `func nextReadLarge(large bool, n int) bool`: large after a small
      read that filled its buffer, small after a large read under
      `smallRead`;
    - `var poisonReleased bool`, set true by an `init` in a `_test.go`
      file, so every released buffer is overwritten with `0xA5` in tests.
  - `carrier.Write(payload []byte) error` becomes
    `carrier.WriteBuffers(bufs [][]byte) error`.

- [ ] **Step 1: Write the failing tests.**
  - `TestWriteBuffersSendsWhatWriteSends`. Over a recording `net.Conn`,
    `WriteBuffers` of 1, 3 and 300 slices puts on the wire exactly the
    bytes `Write(bytes.Join(...))` does. That covers the 7-, 16- and
    64-bit length forms, and an empty slice in the middle.
  - `TestTheReadSizeFollowsTheStream`:
    - `nextReadLarge(false, smallRead)` is true;
    - `nextReadLarge(false, smallRead-1)` is false;
    - `nextReadLarge(true, smallRead-1)` is false;
    - `nextReadLarge(true, largeRead)` is true.
  - `TestReleasedBuffersGoBackByCapacity`:
    - a 4 KiB and a 64 KiB buffer released and taken again come back with
      the same capacity, poisoned with `0xA5`;
    - a buffer of any other capacity is ignored.
  - `TestABurstyBackendIsRelayedExactly`. Through the chain:
    - the backend sends 1 byte, then 3 MiB, then 10 bytes, then 3 MiB, with
      pauses;
    - the client receives every byte in order;
    - a 16 MiB transfer then still completes. Credit did not drift.
  - `TestStreamsClosingMidTransferNeverCorruptOthers`. Under `-race`:
    - 32 streams on one session download 4 MiB each;
    - every second stream is closed half-way;
    - the other 16 receive their bytes exactly, which a poisoned released
      buffer would break.
  - `TestAFailedCarrierWriteEndsTheSession`: a `testCarrier` whose
    `WriteBuffers` fails makes `Serve` return, and no buffer is released
    twice. In tests, `releaseReadBuffer` panics when handed a buffer that is
    already entirely `0xA5`, which is what a second release looks like.
- [ ] **Step 2: Run them red.**
  Run: `go test -run 'WriteBuffers|ReadSize|ByCapacity|Bursty|ClosingMidTransfer|FailedCarrierWrite' ./internal/webrelay/...`
  Expected: FAIL to compile. The functions do not exist.
- [ ] **Step 3: Implement.**
  - **`pump`:** takes `getReadBuffer(large)` for each read and spends
    `min(len(buf), chunk)`. It pushes `frame.NewData(id, buf[:n])` without
    copying, releases the buffer itself when `n == 0`, and updates `large`
    with `nextReadLarge`.
  - **`writeLoop`:** builds vectors with `BatchVectors`, reusing its
    `vecs` and `headers` slices across batches. It calls `WriteBuffers`,
    then releases every DATA payload in the batch. On a write error it
    cancels and releases nothing.
  - **`testCarrier.WriteBuffers`:** joins the slices and sends them on as
    one message.
- [ ] **Step 4: Run the packages.**
  Run: `go test -race -count=3 ./internal/webrelay/... ./internal/testclient/`
  Expected: PASS.
- [ ] **Step 5: Commit.**
  `perf(webrelay): pooled, right-sized reads and one vectored write per message`.

### Task 5: sessions — tombstones, deletion, the bridge page

**Files:**
- Modify:
  - `internal/webrelay/session.go`: `tombstones`, `Serve`;
  - `internal/webrelay/page/page.go`: `Document`, `Render`.
- Test:
  - `internal/webrelay/session_test.go`;
  - `internal/webrelay/relay_proxy_chain_test.go`: unskip
    `TestADeletedSessionStopsServing`;
  - `internal/webrelay/idle_memory_test.go` (new);
  - `internal/webrelay/page/page_test.go`.

**Interfaces:**
- Produces:
  - `page.Document` becomes `{Header http.Header; parts [][]byte}`, with
    `func (d Document) HTML() []byte`, which joins the parts for tests. Its
    `WriteTo` writes the parts in order. The static script is one part,
    shared and never copied.
  - `newTombstones(size int)` allocates nothing up front. The ring and map
    grow to at most `size`, and forgetting is unchanged.

- [ ] **Step 1: Write the failing tests.**
  - `TestTombstonesForgetTheOldestPastTheirSize`. The existing ring
    semantics hold: size 3, add 1..5, `has` is false for 1 and 2 and true
    for 3..5. This one passes today; it is the guard.
  - `TestAnIdleRelaySessionHoldsLittle`, in `idle_memory_test.go`.
    - Setup: an origin whose backend is a listener that accepts and holds,
      as in `TestARealClientCanReachTheBackend`. Open 64 sessions of one
      stream each with `testclient` at `ReadBufferSize: 4 << 10`, each
      proven by one echoed byte through a backend that echoes once.
    - Assert: heap growth per session is under 48 KiB. That is the relay
      under 32 KiB, the spec's bound, plus the test client's share, pinned
      under 16 KiB by `TestAnIdleSessionHoldsLittleMemory`. Today's 88 KB
      tombstone set alone fails it.
  - `TestADeletedSessionStopsServing`, unskipped.
  - `TestRenderDoesNotCopyTheScript`. Over 100 renders, `TotalAlloc` grows
    by less than 4 KiB per render (today about 23 KB). `HTML()` still
    equals the bytes the existing golden assertions expect.
- [ ] **Step 2: Run them red.**
  Run: `go test -run 'Tombstones|IdleRelaySession|DeletedSession|DoesNotCopyTheScript' ./internal/webrelay/...`
  Expected:
  - `TestAnIdleRelaySessionHoldsLittle` fails, over 48 KiB;
  - `TestADeletedSessionStopsServing` fails ("the stream of a deleted
    session must end");
  - `TestRenderDoesNotCopyTheScript` fails;
  - the tombstone guard passes.
- [ ] **Step 3: Implement.**
  - **Tombstones:** grow lazily, with a `size` field replacing
    `cap(ring)`.
  - **`Serve`:** registers
    `stop := context.AfterFunc(s.ctx, func(){ s.conn.Close(ws.CloseNormal, "") })`
    and `defer stop()`. `ws.Conn.Close` is already idempotent.
  - **`Render`:** builds the parts:
    - the static prefix;
    - the nonce, and the boot JSON;
    - the shared script;
    - the static suffix.
  - **Callers:** `origin.go` keeps calling `document.WriteTo(w)`; tests use
    `doc.HTML()`.
- [ ] **Step 4: Run the packages, and the browser harness.**
  Run: `go test -race ./internal/webrelay/...` and `MTG_REQUIRE_BROWSER_HARNESS=1 go test ./internal/webrelay/page/`
  Expected: PASS.
- [ ] **Step 5: Commit.**
  `fix(webrelay): a deleted session ends; idle sessions and bridge pages cost little`.

### Task 6: the after figures and the report

**Files:**
- Create:
  - `benchmarks/results/2026-10-03-web-speed-after.txt`;
  - `benchmarks/results/2026-10-03-web-speed-after-tierB.md`;
  - `benchmarks/results/2026-10-03-web-speed-report.md`.

- [ ] **Step 1: Run the full gate.**
  `MTG_REQUIRE_BROWSER_HARNESS=1 go test -count=2 -race ./...`, then lint
  (`config verify`, `run`, `fmt --diff`), then `govulncheck ./...`.
  Expected: all clean.
- [ ] **Step 2: Run the after figures on the box.** Same commands as
  Task 1 Step 2, at this commit. Also take a CPU profile of
  `BenchmarkDoor/web/upload/conns=16` and `BenchmarkDoor/web/download/conns=16`,
  3 s each. Then remove `/root/mtg-bench`.
  Expected: every row passes.
- [ ] **Step 3: Write the report.** It contains:
  - benchstat before against after, at both `GOMAXPROCS`;
  - the Tier B rows side by side, with dd as the reference;
  - the profile heads after;
  - each spec target met or missed, a missed one with its profile;
  - whether the upload profile still shows zeroing (`memclr`). That is
    the condition for a later reference-counted pool.
- [ ] **Step 4: Commit.**
  `bench: the WEB relay after -- by the targets, met or missed`.
