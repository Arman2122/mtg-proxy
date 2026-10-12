# Rotation of a shared secret with an overlap period — design

Date: 2026-10-08. Revision 3. It follows two advisor rounds, an independent adversarial review
(1 blocker, 4 majors, 14 minors) and a scoped re-review of revision 2 (0 blockers, 1 major,
13 minors; verdict SOUND_WITH_FIXES). See "Review dispositions". Status: ready for the plan,
under delegation. Piece R of the shared-secret program (A
handshake at scale — done; B per-address governance — done, on `feat/client-governance`; **R
this piece**, on `feat/secret-rotation`, stacked on B; C bounded slow-reader queue; D
per-address web-profile shaping).

## The goal, as stated

One shared secret (a "link") is handed to many people. When the link leaks, or when someone who
had it must lose access, the operator has to retire it. Today the only tool is re-keying the
secret, which cuts every legitimate holder at once. Wanted: **rotation with an overlap**. Issue
a new key under the same secret name, keep accepting the OLD key for a bounded overlap so people
can move to the new link, then stop accepting it and close its live streams. Kick and bans
(piece B) are the per-address half; rotation is the "retire a leaked link" half. The change must
be strictly additive.

## Non-goals

- **Rotating secrets the panel manages.** The panel regenerates its config file from its own
  records and re-sends its stored key, so it would undo a rotation. Panel deployments keep
  today's behaviour: a panel re-key is immediate. §9 describes how the panel could adopt
  rotation later.
- **An overlap on the WEB transport.** The relay keeps serving primaries only. §8.1 explains
  why, and shows that old WEB capabilities still never reach a cover site.
- **Identifying or excluding a leaker who is still in the group.** Rotation retires a link that
  escaped. Anyone who receives the new link can leak it again; bans and the per-address controls
  are the tools for that.
- **Per-key traffic accounting.** Traffic on a retiring key is billed to the name, under the
  name's quota and limits.
- **SIGHUP for `run`.** It is not added (D27).
- **A management-API write path for rotation** (D18).

## Where things stand (verified in the code, 2026-10-08)

- `secretSet` (`mtglib/proxy_secrets.go`) is an immutable, name-sorted snapshot. Each name has
  exactly one `Secret`, so one key. `buildCandidates` makes one FakeTLS `Candidate` per hosted
  (ee) secret in name order and drops later repeats of a key. `candIdx[pos]` is the position's
  name index. `candByName` maps a name to ONE position.
- **FakeTLS door** (`doFakeTLSHandshake`): parse and SNI gate against `set.hostnames`, then
  hinted positions (`hintedPositions`, up to 16 names from `matchHints`, each resolved through
  `candByName`), verified outside the budget. Then `reserveScan` charges
  `len(set.cands)-tried` candidates and `scanCandidates` scans the rest. On a match,
  `completeFakeTLS` → `attribute` (sets `ctx.matchedSecretKey = set.secrets[i].Key[:]`) →
  `fake.SendServerHello(…, set.secrets[idx].Key[:], …)`. The inner obfuscated2 handshake
  (`doObfuscatedHandshake`) reads `ctx.matchedSecretKey`. The charge is refunded only after
  `admit` succeeds (`ServeConn`).
- **Obfuscated door** (`doObfuscatedEntry`): builds `keys` from EVERY secret, whatever its mode,
  for each handshake. `obfuscation.MatchHandshake` returns the first index that decrypts to an
  honoured tag. There is no dedupe and no budget, only the per-IP failure limiter.
- `closeStaleConns` compares **the key alone, per name**. If a name's key changed, every live
  stream of that name is closed. Live streams are in `p.liveConns[name]`.
- **There is a race today.** `attribute` runs before `tryRegisterConn`, and on the ee door the
  server's flight is sent in between. A re-key swapped in during that window finds the stream
  not yet registered, so it is not closed. The stream then registers with a key the set no
  longer has. Nothing in `tryRegisterConn` re-checks the key.
- Expiry of a user (`ExpiresAt`) is checked exactly at admission (`checkLimits`). Live streams
  are closed by the maintenance sweep every `denySweepInterval` = 5 s (`closeDeniedConns`).
- The API mutators (`PutSecret`, `DeleteSecret`, `SetGlobalAdTag`) rebuild from
  `set.toConfig()` under `reloadMu`. `handlePutSecrets` builds a whole new `SecretConfig` from
  the request body. All of them go through `swapSecretConfigLocked`. API mutations are
  in-memory only: the next `POST /reload` or a restart re-reads the file (documented in
  Multi-User-and-API.md).
- **Config.** `[secrets]` maps a name to a string. Parsing goes TOML → `tomlConfig` → JSON →
  `Config`. `unknownKeys` re-decodes strictly to name the keys it dropped. `run` logs them,
  `run --check` refuses them (`checkConfig`), and `doctor` lists them. `Config.String()`
  redacts `secret`, `apiToken`, `adTag` and the values of `secrets` and `secretAdTags`.
- **env.go.** `SECRET`/`MTG_SECRET` "fully defines the secret set" and clears `Secrets`,
  `SecretAdTags` and `SecretLimits`.
- **Reloading.** `run` has no SIGHUP handler: SIGHUP today ends the process (Go's default).
  The proxy reloads on `POST /reload` (`makeSecretsReloader` re-reads the file) or on a
  restart. The WEB relay reloads on SIGHUP and also watches the file every 2 s, applying a
  change once it has held still for two ticks (`web_relay_watch.go`).
- **WEB relay** (`internal/webrelay`). It derives one capability per primary from
  `WebSecret(secret)` (the dd spelling) and the WEB host. `Lookup` serves the bridge.
  `IsAuthentic` (tier two) answers an authentic-but-unusable value with a local 404. Anything
  else is tier three and goes to the cover site, which for `cover-upstream` is a third party.
- **`Secret.Set` echoes its input in one error** (`"hostname cannot be empty: %s"`). This is a
  pre-existing leak for `[secrets]` values; this piece does not reuse that parser's errors for
  retiring values (D21).
- **Panel** (`Penhoon Panel/internal/mtproto`, read-only):
  - It renders the whole file with `renderConfig` and writes it non-atomically
    (`os.WriteFile(path, …, 0o640)`) to `<bin>/mtproto/mtg-<id>.toml`. `[secrets]` is always
    the last table.
  - It **never reads the file back**: its only `os.ReadFile` is of `/proc/<pid>/cmdline`.
  - It applies a client change in place with `PUT /secrets` (`applySecrets`) and falls back to
    a restart if that does not return 200. The package comment still says `POST /reload`;
    that comment is stale.
  - It decodes `/stats` non-strictly, renders no `usage-state-file`, runs `run --check` on a
    staged binary over its own file, and sends SIGHUP only to the relay.

## The invariant, and why the file is its source of truth

**Invariant R0:** no loss of rotation state can make a leaked key the primary again, or make a
key accepted after its overlap has ended. Every way state can be lost resolves toward
*not accepting* the old key.

Rotation needs two writes: a new primary, and a grant for the old key. They have opposite
safety properties:

- **The new primary is dangerous to lose.** Lose it, and the next load reads the old primary
  from the file: the leaked key is the primary again, and the new link already handed out is
  dead.
- **The grant is safe to lose.** Lose it, and the old key stops being accepted early. That
  cuts users, but never revives anything.

So the new primary must be in the file before anything relies on it. The grant is safe in
memory or in the file, but it has to survive restarts to be useful, and the proxy never writes
its config file (the panel owns it, and the usage-state file must not be touched). **The file
therefore carries both** (D1): the CLI edits it, and the proxy reloads it.

| Event | Primary afterwards | Old key afterwards |
|---|---|---|
| `POST /reload` of an unchanged file during the overlap | the file's (the new key) | accepted until `until`; no stream closed |
| reload or restart after `until` | the file's | not accepted: an expired entry is inert (D11). On a reload, its live streams are closed by that swap (§4.1, the held-key predicate) |
| the expiry sweep after `until` | unchanged | not accepted; its live streams closed at the next sweep tick (5 s), one tick later per collision with a reload or mutation that does not swap (§4.2) |
| a stream racing an expiry or re-key swap between `attribute` and registration | the swap's | refused `key_revoked` at registration, or closed by the swap's walk. This holds **only because the re-check loads the set inside `liveMu`** (§4.3, L5b) |
| restart during the overlap | the file's | accepted until `until` |
| crash after the file write, before any reload | at restart, the file's (new) | per the file |
| crash during the write | the old file is intact (atomic rename) | per the old file: no rotation happened |
| panel rewrites its file (no `[[retiring-secret]]`) and restarts | the panel's | not accepted |
| `PUT /secrets` (panel or operator) | the PUT's | in-memory entries of names the PUT keeps survive; none are created (D17) |
| `POST /secrets` re-keying the name back onto its retiring key K1 ("revert") | K1, in memory | the retiring entry is dropped (rule 6); the new key's streams close. This is one of the API calls that make the leaked key primary on purpose: a `PUT /secrets` naming the retiring key as the name's primary does the same, and a POST or PUT that gives ANOTHER name the retiring key makes it that name's primary (drop line `key_of_other_secret`, Warning; revision 4, Task 6's review). The next reload returns to the file (§5.1) |
| a hand edit writes `retiring-secret = "x"` (a scalar, not a table) | the previous set's, on a reload (the whole file is refused); none on a start (the process does not start) | as before the edit. The one shape that blocks a load (§1.1, M4) |
| an older binary reads the file | the file's | not accepted: the table is an unknown key (logged; `--check` refuses) |
| the wall clock steps back after `until`, same process | — | not accepted: the config layer and the engine both read the process's one high-water clock (D10) |
| the wall clock is behind the high-water mark (an episode), and a reload arrives | the file's | judged by the mark: an entry the mark has passed is dropped as expired and logged as such, even though the wall clock says it is unexpired. `run --check` and `doctor`, separate processes on the wall clock, may still list it as unexpired: informational only |
| the wall clock steps back after `until`, then a restart | — | **accepted again for up to the step**. Residual risk; `--prune` removes the entry for good (Risks) |

## Decisions

Each is numbered and justified where it is made. The ones most worth auditing are repeated in
"Decided by the agent".

- **D1** The config file is the only source of retiring keys. No API route writes one, and the
  proxy never writes the file.
- **D2** Representation: an array of tables, `[[retiring-secret]]`, with `name`, `secret` (a
  value) and `until`.
- **D3** `until` is an absolute RFC 3339 instant with an explicit offset.
- **D4** A problem in a retiring entry never blocks a load. `run` and reload drop the entry with
  a warning, which kills that old key. `run --check` refuses the file. There is one exception,
  stated rather than hidden: a scalar where the table belongs (`retiring-secret = "x"`) is a
  parse error of the whole file (§1.1).
- **D5** Problems, warnings and inert conditions are separated, and two properties hold for an
  unchanged file:
  - **P1:** what `run --check` accepts at *t* it accepts later;
  - **P2:** what `run` does not accept at *t* it never accepts later (R0).

  The cross-name collision is therefore judged against every entry, expired or not, and
  too-far `until` is a warning, not a drop.
- **D6** Caps: 4 per name and 4,096 in all (drops). `until` more than 720 h after the load is a
  warning under `run`, a refusal under `--check`, and never written by the CLI.
- **D7** A retiring value may have any mode and any host. Door behaviour follows the value's own
  mode.
- **D8** Key uniqueness: the primary always wins. A cross-name collision is a problem.
- **D9** Retiring FakeTLS candidates come after every primary candidate. Every new field is nil
  when there is no retiring key.
- **D10** Expiry is judged by a high-water wall clock: one `mtglib.RotationClock` per process,
  handed to both the config layer's reloader and the engine (`ProxyOpts.RotationClock`).
- **D11** Expiry is exact at admission, and live streams close at the next 5 s sweep tick, or
  in any swap before it. Each time the sweep's `TryLock` collides with a reload or mutation
  that does not swap, the close moves one tick later. There is no extra grace.
- **D12** A hinted name tries its primary, then its retiring keys. At most 32 hinted
  verifications per hello.
- **D13** The budget is unchanged. Retiring candidates are charged like any other candidate.
- **D14** The matched key, not the name's primary, travels to the server's flight and to the
  inner handshake.
- **D15** `closeStaleConns` decides per stream, by the stream's own key. Its per-name fast path
  compares the **held-key sets** (primary plus every retiring key a set holds), with no clock.
- **D16** Registration re-checks the key, loading the set **inside `liveMu`** before the ban
  re-check. This also closes the pre-existing re-key race.
- **D17** API mutations preserve retiring entries. A removal drops them, and a re-key onto a
  retiring key drops that entry. `SecretConfig.Retiring` has one meaning everywhere (nil is
  none); the HTTP PUT handler keeps entries through an unexported keep-merge.
- **D18** No `rotate` route and no write field.
- **D19** Read-only view: four scalars inside the existing objects, and the feature string
  `secret-rotation`.
- **D20** `retiring_connections` is computed at read time from each stream's key.
- **D21** Key material never appears in logs, errors, API responses or `Config.String()`.
- **D22** A new CLI command, `rotate-secret`. It keeps the mode; a mode change is a hand edit.
- **D23** A surgical text edit, verified by a re-parse diff.
- **D24** Atomic write discipline: temp file, fsync, rename. There is no in-place mode and no
  backup copy.
- **D25** Refuse a file that looks panel-managed (override with `--force`).
- **D26** `--reload`: pre-check the running binary, reload, read back.
- **D27** No SIGHUP handler for `run`.
- **D28** The WEB relay serves primaries only and recognises retiring capabilities as tier two.
- **D29** The `SECRET` environment override clears retiring entries.
- **D30** Downgrade: an older binary ignores the table, which kills the old key.
- **D31** `retiring_last_seen` records admissions made under a retiring key.
- **D32** `--overlap` is required (no default); `--overlap 0` is an immediate re-key.

## 1. Config: `[[retiring-secret]]`

### 1.1 Shape (D2, D3)

```toml
# The previous key of a secret, accepted until `until`, after the secret was given a new key.
# Written by `mtg-proxy rotate-secret`; may be written by hand. Must sit after every top-level key.
[[retiring-secret]]
# added by mtg-proxy rotate-secret at 2026-10-08T09:30:00Z
name   = "shared"
secret = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
until  = "2026-10-09T09:30:00Z"

[secrets]
shared = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

- **`name`**: a name in `[secrets]`, or `"default"` with the single top-level `secret` (the name
  `GetSecrets` gives it).
- **`secret`**: the old link's value, hex or base64url, any mode (ee/dd/plain), parsed by the
  same rules as a `[secrets]` value. It is a VALUE, never a TOML key or table name (D21).
- **`until`**: an RFC 3339 date-time **with an offset** (`Z` or `±hh:mm`), quoted or as a TOML
  offset date-time. A local date-time, a date alone, or any other type is a problem (§1.3).
  Comparisons are of instants, so the offset only changes the spelling. The CLI always writes
  UTC `Z` to the second.

**Alternatives rejected:**
- `[secret-rotation.<name>]`, a table per name: cannot hold two retiring keys for one name.
- A `[retiring-secrets]` map from name to value: has no room for `until`.
- Inline arrays inside `[secrets]`: change a table the panel writes and reads its own way.
- A Unix-seconds `until`: unreadable in a file a person audits after a leak.
- `expires`: already means the user's own expiry in `[secret-limits]`.
- A relative `overlap = "24h"`: lost state would revive it, because a restart re-reads it as
  "24 h from now". An absolute `until` cannot.

**Placement:** like `[[listener]]`, the block must sit after every top-level key. The CLI
inserts it immediately before the `[secrets]` header (§7.3), so `[secrets]` stays last. That is
the layout the example config and the panel use, and the one an operator appends users to.

**Parsing:** `tomlConfig` gains

```go
RetiringSecrets []struct {
    Name   any `toml:"name"   json:"name"`
    Secret any `toml:"secret" json:"secret"`
    Until  any `toml:"until"  json:"until"`
} `toml:"retiring-secret" json:"retiringSecrets,omitempty"`
```

`Parse` normalises each field to a string before the JSON step:
- a string stays as it is;
- a `time.Time` (a TOML offset date-time) becomes RFC 3339 with nanoseconds;
- anything else becomes `fmt.Sprint(v)`, marked as having the wrong type.

The fields are `any` so that a wrong TOML type is a problem of that one entry (§1.3), not a
failure to parse the file. Two facts about the table's shape, both verified by the review
against the pinned go-toml:

- **A single `[retiring-secret]` table** (one bracket pair instead of two, the common typo)
  decodes into the slice as **one entry**, exactly as `[listener]` does today. It does not
  block a load. Test C15 pins it, and the CLI's locator recognises that header kind too
  (§7.3).
- **A scalar where the table belongs** (`retiring-secret = "x"`, or any non-table value) is a
  parse error of the whole file, as for every other table. That is **the one hand edit of a
  rotation block that blocks a load.** At start the process does not start. On a reload, the
  previous set stays active, and if the same edit also re-keyed `[secrets]`, **the leaked key
  stays the primary** until the file is fixed. How it surfaces:
  - `run --check` and `rotate-secret` (step 1 of §7.3) refuse it with the parser's own error;
  - `POST /reload` answers 500 with it, and the reload failure is logged at Warning;
  - the FAQ says: if `run` refuses the file after a hand edit of a rotation block, the error is
    in the table's shape, not in an entry.

  **Rejected:** decoding the whole table as `any` and normalising every shape. That would
  remove this last blocking case, but it would also lose go-toml's strict detection of a
  misspelt field inside the block, which would then have to be re-implemented. `rotate-secret`
  never writes this shape.

A UTF-8 byte-order mark at the start of the file is refused by today's parser
(`toml: invalid character at start of key`). This piece does not change that.

`Config` gains the field `RetiringSecrets []ConfigRetiringSecret
json:"retiringSecrets,omitempty"`. `ConfigRetiringSecret` has `Name`, `Secret` and `Until` as
raw strings, plus an **unexported** wrong-type mark.
- **The values are not parsed during the JSON decode,** because a `TextUnmarshaler` error would
  carry no index and might echo the value.
- **How the mark is set (m8 of the second review).** An unexported field neither crosses the
  JSON step nor appears in `Config.String()`. So `Parse` sets the mark on
  `conf.RetiringSecrets[i]` **after** the JSON decode, from the record its normalisation pass
  over `tomlConf.RetiringSecrets` kept: which fields of entry `i` had the wrong TOML type.
- `omitempty` keeps `Config.String()` byte-identical for every file without the table,
  including the panel's.

### 1.2 Reading it: `(*Config).GetRetiringSecrets(now) RetiringReport`

The method follows the package's pattern of a field `X` with a method `GetX` (`Secrets` and
`GetSecrets`). A method named like the field would not compile (m1 of the second review). It
returns a small struct (m7 of the second review), so every output the callers need has a
channel:

```go
type RetiringReport struct {
    Usable  []mtglib.RetiringSecret // what the engine is handed (rule-4 entries included)
    Lines   []string                // one per problem or warning; --check refuses any; logged at Warning
    Expired int                     // rule-2 entries: the Info summary, doctor's count and the --prune hint
    Notes   []string                // Info lines: rules 6 and 7 (inert duplicates, own-primary keys)
}
```

It is pure (no logging, no state) and takes `now`, so a test injects the clock.

Every caller uses it, and each says which clock its `now` comes from:
- inside `run` (the start-up and the reloader): the process's one `RotationClock` (§2.3, D10);
- `run --check`, `doctor` and `rotate-secret`: separate short-lived processes with no
  high-water history, so they use `time.Now()`.

`Validate()` does **not** call it (D4). So `web-relay` and `access` never fail because of a
retiring entry, and `doctor` reads the file normally and reports the lines as a failed check of
its own (§1.4), not as an unreadable config.

### 1.3 Problems, inert entries, and why they never block a load (D4, D5)

Each entry is classified in this order.

| # | Condition | Class | Under `run` and reload | Under `run --check` |
|---|---|---|---|---|
| 1 | `name` empty or wrong type; `secret` wrong type, unparseable, or an all-zero key; `until` missing, wrong type, without an offset, or not RFC 3339 | problem (does not depend on time) | entry dropped, warning | refused |
| 2 | `until` ≤ now | **inert** (expired) | ignored; one Info summary line naming the count and suggesting `--prune` | accepted |
| 3 | `name` not a configured secret | problem | dropped, warning | refused |
| 4 | `until` > now + 720 h (`mtglib.MaxRetiringOverlap`) | **warned** (an over-long grant, still bounded by its own `until`) | **kept**, warning at every load | refused |
| 5 | the key equals any other name's primary key, or the key of **any** syntactically valid entry of another name, **expired or not** (a pure function of the file's text, so it does not depend on time) | problem | dropped, warning (both colliding retiring entries are dropped; a primary is never touched) | refused |
| 6 | the key equals its own name's primary key | inert (the primary already accepts it) | ignored, Info | accepted |
| 7 | two unexpired entries of one name with the same key | inert duplicate | collapsed to one with the later `until`, Info | accepted |
| 8 | more than 4 unexpired entries for one name (`mtglib.MaxRetiringPerSecret`), or more than 4,096 in all (`mtglib.MaxRetiringSecrets`) | problem | keep the 4 latest `until` per name, then the 4,096 latest overall (ties broken by name, then key bytes); drop the rest, warning | refused |

**Why a problem drops the entry instead of refusing the file.** A refused reload keeps the
previous set. Take a hand edit that re-keys `[secrets]` and adds a retiring block with a typo
in `until`. Refusing it would leave the **leaked key as the primary** and the new key dead,
which is the opposite of what the operator asked for. A dangling block would also block the
removal of a user. And `Validate()` runs inside `web-relay` (at start and on every watcher
reload), `access` and `doctor`, none of which serves these keys: the relay only recognises
them, and `doctor` only reports them. Dropping fails toward
*killing* the old key, which R0 permits. The cost is that users of that old link are cut
early, and the warning (at the default log level) says why. This is the same split as unknown
keys: logged by `run`, refused by `--check`.

**Two properties in time, both required, both tested.** In each, the file is unchanged and
*t′ > t*.

- **P1 (`--check` is monotone):** a file `--check` accepts at *t* is accepted at *t′* (§12,
  C9).
  - Rules 1 and 5 do not depend on time.
  - Rules 3 and 8 look only at unexpired entries, a set that only shrinks.
  - Rule 4 compares `until` with `now + 720h`, and `now` only grows.
  - Entries only ever move into rule 2.
- **P2 (`run` never revives, which is R0):** an entry that `run` does not accept at *t* is not
  accepted at *t′* (§12, C12). Rule by rule:
  - 1 is constant.
  - 2: an expired entry stays expired. Within one process the high-water clock guarantees it;
    across a restart, only the wall clock does (Risks).
  - 3 depends on `[secrets]` only.
  - 5 is a pure function of the text. This is why it compares against expired and dangling
    entries too. Judged against unexpired entries only, the collision would disappear when the
    other name's entry expired, and a reload would then accept a key it had dropped.
  - 6 and 7 never drop a grant: the key is either the primary's, or kept with the latest
    `until`.
  - 8 drops the entries that expire first. Its order (`until` descending, then name, then key
    bytes) is fixed, and the population it ranks only shrinks with time. So every entry ranked
    above a dropped one is still unexpired, and still ranked above it, for as long as the
    dropped one is unexpired.
  - Rule 4 is why it is a **warning, not a drop**. Any comparison with `now` that drops an
    entry today would accept it once `now` has grown (a block 721 h away is dropped now and
    accepted an hour later). So `run` keeps it, bounded by its own `until`, and warns at every
    load; `--check` refuses it, and `rotate-secret` never writes one.

A drop caused by an API mutation (§5.1, a re-key onto a retiring key) is not covered by P2. The
next reload returns to the file, and the file's grant is still in force: it is not a key past
its overlap.

Nor is a drop undone by a **deliberate edit** covered by P2. Example: `--end-overlap` for one
name shrinks the unexpired population, and can bring another name's entry back under the rule 8
cap. That is a changed file, not lost state, and the entry is still bounded by its own `until`.

**Messages are value-free.**
- A problem: `retiring-secret #<n> (name "<name>"): <reason>; the entry is ignored and its key
  is not accepted`.
- The rule-4 warning: `retiring-secret #<n> (name "<name>"): until is more than 720h away; it
  is honoured, but an overlap is a migration window, not a second key: shorten it (run --check
  refuses this file)`.

`<n>` is the 1-based position in the file. The reason never contains the secret. `until` is not
a credential and may be echoed.

### 1.4 Wiring

- **The clock.** `runProxyWith` gains a `now func() time.Time` parameter beside `listen`:
  `runProxy` passes `time.Now`, and the `run_proxy_loop_test.go` harness passes a fake (m4 of
  the second review). Right after building the logger, it builds the process's one clock,
  `clock := mtglib.NewRotationClock(now, onBehind)`, where `onBehind` logs the §2.3 Warning with
  the run's logger.
  - It hands that one clock to both `makeSecretsReloader(configPath, logger, clock)` and
    `ProxyOpts.RotationClock`.
  - The reloader is built before `NewProxy` and has no handle on the proxy, so this shared
    value, and no package global, is how the config layer and the engine read one clock.
  - `runProxy` is the only production caller, for both `run` and `simple-run` (whose reloader
    is nil), so there is no second construction site.
- `makeSecretsReloader` calls `conf.GetRetiringSecrets(clock.Now())` and puts
  `Retiring: report.Usable` in the `SecretConfig` it returns. On start-up and on every reload it
  logs each of `report.Lines` at Warning, in `warnUnknownKeys`' wording style, and
  `report.Expired` and `report.Notes` at Info.
- `runProxyWith` passes `ProxyOpts.RetiringSecrets = report.Usable` (judged on the same clock)
  and logs the report once.
- `checkConfig` refuses when there are unknown keys **or** `report.Lines` is non-empty:
  `errRetiringProblems`, listing them.
- `doctor` lists `report.Lines` and shows `report.Expired` with the `--prune` hint. A retiring
  line **fails the doctor's verdict**, as an unknown key does (`checkUnknownKeys`); expired
  entries alone do not.

### 1.5 The `SECRET` environment override (D29)

`applyEnvSecret` also sets `c.RetiringSecrets = nil`. The environment "fully defines the secret
set", so a retiring entry for a file name that is no longer in effect would dangle. Clearing it
is the only consistent choice, and it is the kill direction. A test pins it next to the
existing env tests.

### 1.6 `Config.String()` (D21)

`redactConfigCredentials` replaces the `secret` field of every element of `retiringSecrets`
with `[redacted]`. `name` and `until` are kept, for the reason names are kept elsewhere: which
rotations are configured is the point of that log line.
`TestConfigStringRedactsEveryCredential` gains a retiring entry.

## 2. The engine: a secret set with retiring keys

### 2.1 Types (library, additive)

```go
// RetiringSecret is a key a secret name still accepts until Until, after the name was
// given a new primary key. Its traffic is the name's: same quota, limits, bans, stats.
type RetiringSecret struct {
    Name   string
    Secret Secret
    Until  time.Time
}

const (
    MaxRetiringOverlap   = 720 * time.Hour
    MaxRetiringPerSecret = 4
    MaxRetiringSecrets   = 4096
)
```

- `SecretConfig.Retiring []RetiringSecret`, `ProxyOpts.RetiringSecrets []RetiringSecret` and
  `ProxyOpts.RotationClock *RotationClock` (§2.3; nil makes `NewProxy` build its own on
  `time.Now`).
- `SecretConfig.Retiring` has **one meaning wherever a `SecretConfig` is consumed**: the
  complete list, nil meaning none. That holds for `ReloadSecrets`, `ReplaceSecrets` and
  `swapSecretConfigLocked`, and likewise for `ProxyOpts.RetiringSecrets` in `NewProxy`. The
  field's doc comment says so. The keep-merge for
  `PUT /secrets` is an unexported step of the HTTP handler (§5.1), not a second meaning of nil.
- The engine applies rules 2, 3, 5, 6, 7 and 8 again, defensively, for library callers and for
  states only the engine sees (a `POST /secrets` re-key onto a retiring key, an entry that
  expired between the reloader's read and the build). At engine level every rule drops and
  logs; none is an error. Engine rule 2 is the **authority on acceptance**. In the `run`
  process it reads the same clock the config layer read, so the two never disagree except for
  an entry expiring in the microseconds between them, which is logged with reason `expired`.
- The engine judges rule 5 only among the entries and primaries it is handed. The config layer
  has already applied the time-independent form against the whole file, expired entries
  included, before it filters out the expired ones, so P2 holds for the file path.
- The engine does not apply the 720 h cap (a config warning and a CLI rule).

### 2.2 Building the set (D9)

`buildSecretSet` keeps its signature (about 40 test call sites use it) and becomes
`buildSecretSetAt(…, nil, time.Time{})`. The new function is

```go
func buildSecretSetAt(secrets map[string]Secret, perSecret map[string][AdTagLength]byte,
    global *[AdTagLength]byte, limits map[string]SecretLimits,
    retiring []RetiringSecret, now time.Time) (*secretSet, []retiringDrop)
```

`retiringDrop` is `{name string; until time.Time; reason string}`, for logging, with reason one
of `expired`, `dangling`, `same_as_primary`, `duplicate`, `key_of_other_secret`, `over_cap` or
`invalid` (revision 4, Task 1's review: a handed entry whose `Secret` fails `Secret.Valid()`, such as an
all-zero key from a library caller that forgot it, is dropped first of all rather than becoming a
candidate; the config layer's rule 1 still refuses such a block earlier under `--check`, and the
engine never refuses a swap for it). It never holds a key. New `secretSet` fields, **all nil or zero when no retiring entry survives**:

```go
retiring       []retiringEntry   // {nameIdx int; secret Secret; until time.Time},
                                 // sorted by (nameIdx, until desc, key bytes)
retiringOf     map[int][]int     // nameIdx -> indices into retiring
primaryCands   int               // cands[:primaryEnd()] are primaries (primaryCands equals primaryEnd() only when retiring entries exist, and is 0 otherwise); the rest are retiring ee keys
candRetiring   []int             // candRetiring[pos-primaryEnd()] = index into retiring
retiringCands  map[string][]int  // name -> its retiring candidate positions, same order
retiringNext   time.Time         // earliest until in retiring; zero when none
```

- `cands`/`candIdx`/`candByName` are built exactly as today for the primaries, so `candByName`
  still means "the primary's position". The unexpired, surviving **ee** retiring entries are
  then appended in `retiring` order, with `candIdx[pos]` = their `nameIdx`. A retiring key
  never equals any primary key (rule 5/6 at engine level) or another kept retiring key
  (rule 7), so nothing needs a second dedupe.
- `hostnames` (the SNI gate) also takes the host of every kept ee retiring entry. Without that,
  a rotation that also moves the fronting domain (an ee value for a new host) would cut every
  old-link client at the SNI gate. A host only a retiring key names is accepted by the gate
  until the entry expires. That is exactly the status quo before the rotation, and it ends on
  the swap that drops the entry.
- `coverHosts` (what the doppelganger measures) also takes retiring ee hosts, so an old-link
  client gets the same server-flight sizing it got before the rotation. `hostNoise` already
  keeps hosts once measured. The pacing defaults are untouched.
- `frontHost` and `SecretsCanFront` stay **primary-only**. A set whose only ee key is retiring
  cannot front after the expiry, so it is refused now, as today.
- `toConfig()` reconstructs `Retiring` from `retiring` (name, secret, until).
  `SecretConfig.forget(name)` also removes that name's retiring entries.

**Alternative rejected:** interleaving each name's retiring candidates right after its primary.
That puts old-link candidates in front of other names' primaries on every unhinted scan, and
those primaries are the bulk of the traffic. It also makes the no-retiring loop different code.

### 2.3 The rotation clock (D10)

The clock is an exported library type, because two layers of one process must share it (M2 of
the review):

```go
// RotationClock is the wall clock retiring keys expire by, never allowed to run backwards
// within a process. One instance per process, shared by whatever reads a config and the proxy.
type RotationClock struct {
    now      func() time.Time      // time.Now in production; injected in tests
    mark     atomic.Int64          // the latest wall time seen, unix nanos
    behind   atomic.Bool           // the current "wall clock behind" episode was reported
    onBehind func(by time.Duration) // called once per episode; nil logs nothing
}

func NewRotationClock(now func() time.Time, onBehind func(time.Duration)) *RotationClock
func (c *RotationClock) Now() time.Time   // nil pointer: time.Now; zero value: high-water on time.Now
```

- **What `Now()` does.** It returns `max(source(), mark)` and advances `mark` by CAS. `source`
  is `c.now`, or `time.Now` when `c.now` is nil.
- **The zero value is usable (m3 of the second review).** The fields are unexported, so the
  only value a library caller can build without `NewRotationClock` is `&RotationClock{}`. Its
  `now` is nil, and it must not panic. It is therefore a real high-water clock on `time.Now`
  with no `onBehind`. A nil pointer reads plain `time.Now`, with no high-water mark. E5 covers
  both.
- **Who holds it.** `Proxy.rotation` is `ProxyOpts.RotationClock`, or one `NewProxy` builds on
  `time.Now` (with `onBehind` logging through the proxy's logger) when the option is nil.
  `NewProxy` resolves the clock right after it builds its logger and **before** it builds the
  initial set, because that build reads the clock (`proxy.go:182`–`185`). A `Proxy{}` literal
  in a test has nil, which reads `time.Now`.
- **What it governs.** In the `run` process it is the only clock for retiring expiry: the
  reloader's `GetRetiringSecrets(now)` (§1.4), `buildSecretSetAt`'s `now` (including
  `NewProxy`'s initial build), the door checks, the sweep, the registration re-check, the §6.3
  change-log classification and the read-backs.
- **Who does not use it.** `checkLimits` keeps `time.Now()` for a user's own `ExpiresAt`, as
  today. The separate processes in §1.2 (`--check`, `doctor`, `rotate-secret`) use
  `time.Now()`.

**Behaviour during a behind-clock episode** (the wall clock is more than 1 s behind `mark`),
from the moment it starts:
- `onBehind` fires once with the gap;
- the config layer and the engine both judge expiry by `mark`, so an entry whose `until` lies
  between the wall clock and `mark` is expired for both;
- a reload's config layer filters it as inert (rule 2, counted in `report.Expired`), so the
  engine is never handed it; an entry already in the set is dropped by the next swap's build;
- either way its streams close in that swap or at the next sweep, and the §6.3 diff logs
  "overlap ended";
- new handshakes on it are refused at the door;
- when the wall clock passes `mark` again, the episode ends and `behind` resets;
- nothing that `mark` judged expired is accepted again, because `mark` never decreases.

- **Why.** Within a process, an NTP step backwards after `until` must not make a reload of the
  unchanged file accept the old key again (R0).
- **Fail-safe, but silent unless logged.** A forward jump followed by a correction ends early
  every overlap whose `until` falls before the poisoned `mark`, for the rest of the process. So
  the clock reports each episode once through `onBehind`, which `run` and `NewProxy` log at
  Warning when the wall clock is more than 1 s behind `mark`:
  `the wall clock is behind the latest time seen; rotation overlaps are judged by the latest time`,
  with `behind_by`.
- **Rejected:**
  - the monotonic clock alone: it cannot be compared with an absolute `until` read from a file;
  - a wall-clock config layer with the engine as sole authority (the review's other option): it
    works, but it runs two clocks in one process, and the config layer's lines (the expired
    count, the cap's population) would disagree with what the proxy does during an episode;
  - a package-level clock: a global that tests would have to reset.
- **The restart gap (m12 of the review).** The only way to close it would be to persist `mark`:
  a tiny high-water file beside the usage-state file, never in it. It is not done here, because
  the proxy writes no new file in this piece. It is noted as the one future fix.

## 3. The two doors

### 3.1 FakeTLS (D12, D13, D14)

```
hinted          := p.hintedPositions(ctx, parsed, set)      // per hinted name: its primary position
                                                            // if it has one, then its retiringCands
                                                            // whether or not it has one; deduped;
                                                            // at most 32
pos, tried      := p.verifyHinted(parsed, set, hinted)      // a retiring position whose until has
                                                            // passed is passed over, unverified
res, …          := p.reserveScan(…, len(set.cands)-tried, …) // unchanged
pos, scanned    := p.scanCandidates(parsed, set, skip)      // loop 1 over cands[:primaryEnd()] is
                                                            // today's loop byte for byte; loop 2 over
                                                            // cands[primaryEnd():] checks until first
m               := set.matchAt(pos)                         // {idx, key *[16]byte, retiring int}
p.completeFakeTLS(ctx, rewind, set, parsed, m)              // SendServerHello(m.key)
```

- **Expiry at the door (D11).** `now` is read lazily, once per hello and only if a retiring
  position is reached. A candidate with `until ≤ now` is never verified. A hello under an expired
  key matches nothing and is fronted with the same bytes as a wrong secret. Between `until` and
  the next swap that drops it (the sweep, within one tick, or any reload; §4.2), the expired
  candidate is still in `cands`, so the scan charge counts it: an overcharge of at most the
  expired count, never an undercharge.
- **Hints.** A hint is still a name, written only after the whole success path. A client
  admitted under a retiring key leaves the hint `name`, and next time is verified against the
  name's primary (a miss) and then its retiring keys, so a returning old-link client costs 2
  verifications instead of a scan.
  - A name's retiring positions are added **whether or not its primary is a FakeTLS
    candidate**. After an ee → dd rotation the primary has no `candByName` entry, because a dd
    key is no candidate. Today's `if pos, ok := set.candByName[name]; ok` would then skip the
    name entirely, and the old ee link would lose its hint. Test D4b pins this.
  - The hinted list is capped at `maxHintPositions = 32`. Positions past the cap are left to the
    budgeted scan.
  - Without retiring keys the list is at most 16 long, so the cap never bites.
  - The worst case is 32 × 128 blocks (twice today's bound), reachable only from an address
    that holds earned hints for many names, each mid-rotation.
- **Budget (D13).** Unchanged. A retiring candidate counts in `remaining` and in `burstFloor`
  like any candidate. While retiring keys exist, an unhinted scan costs more for everyone.
  §11 has the numbers and the after-restart case.
- **The matched key (D14).** `attribute(ctx, set, m)` sets `ctx.matchedSecretKey = m.key[:]`
  (a slice into the set's own `retiringEntry.secret.Key` or `secrets[i].Key`), plus
  `ctx.attrSet = set` and `ctx.retiringUntil = until` (zero for a primary).
  `SendServerHello` and the inner obfuscated2 handshake therefore use the key the client
  actually holds. Name, ad tag, limits, ip-limit and client-conns all come from `m.idx`, the
  name.

### 3.2 Obfuscated (dd/plain)

```go
keys := make([][]byte, len(set.secrets), len(set.secrets)+len(set.retiring)) // same alloc size when none
for i := range set.secrets { keys[i] = set.secrets[i].Key[:] }
var keyRetiring []int                                         // allocated only when retiring exists
if len(set.retiring) > 0 { now := p.rotation.Now(); for r := range set.retiring {
    if now.Before(set.retiring[r].until) { keys = append(keys, set.retiring[r].secret.Key[:]); keyRetiring = append(keyRetiring, r) } } }
```

- An `res.Index ≥ len(set.secrets)` maps through `keyRetiring` to the entry, and from there to
  its name and key.
- Primaries come first, as on the FakeTLS door. Order changes no attribution, because keys are
  unique (D8); it only decides how far the trial loop runs.
- Every refusal takes the existing single exit (`denyObfuscated`).
- **Modes (D7).** A retiring value of any mode is tried here, as every primary is today. Only an
  ee value also becomes a FakeTLS candidate. A name may move from dd to ee (or back) with an
  overlap: the old dd link keeps working on the obfuscated listener and the new ee link on
  `bind-to`. A retiring dd/plain key on a proxy with no `[[listener]]` is unreachable, as such a
  primary is. Start-up logs it at Warning with the existing "not served by any listener" wording
  and the name.

## 4. Expiry and the stream lifecycle

### 4.1 `closeStaleConns` decides per stream (D15)

`closeStaleConns` keeps its contract ("a stream whose key the new set no longer accepts is
closed") but decides it **per stream**, and gains a `now` parameter.

Two sets per name, kept apart on purpose:

- **Held-key set:** the primary plus every retiring key a set *holds*, expired or not. It is a
  pure function of the set and reads no clock. For a name the set does not have, it is the
  **empty set** (m9 of the second review), so a name re-added after a removal never takes the
  fast path.
- **Accepted-key set:** the primary plus the retiring keys with `until > now`; empty for an
  absent name.

`swapSecretConfigLocked` reads `now` once from the rotation clock and passes the same value to
`buildSecretSetAt` and to `closeStaleConns(oldSet, newSet, now)`. For each name in
`liveConns`:
- the name is absent from `newSet` → close all of its streams (as today);
- the name's **held-key sets** in `oldSet` and `newSet` are identical → skip the name (fast
  path);
- otherwise, close each stream whose `matchedSecretKey` is not in **`newSet`'s accepted-key
  set at `now`**.

**Why the fast path must not read the clock (B1 of the review).** Revision 1 compared two
*accepted* sets judged at the swap's `now`. At the expiry sweep, old = {K2, K1→T} and new = {K2}
judged at `now ≥ T` are both {K2}. They looked identical, the name was skipped, and **every K1
stream stayed open forever**: newSet has no retiring entry, so no later sweep looks at the name
again. A reload after `T` had the same defect. Comparing what the sets hold avoids both: old
holds {K2, K1} and new holds {K2}, so they differ, and the K1 streams are closed.

The outcomes:

| Swap | Held: old → new | Result |
|---|---|---|
| no retiring keys, unrelated change (an ad tag, another user) | {K} → {K} | skipped, as today |
| re-key, no overlap | {K1} → {K2} | every K1 stream closed, as today |
| rotation | {K1} → {K2, K1} | per stream; K1 is accepted in new, so nothing is closed |
| reload during the overlap, unchanged file | {K2, K1} → {K2, K1} | skipped |
| expiry sweep, or a reload after `T` | {K2, K1} → {K2} (the build at `now ≥ T` dropped K1) | the K1 streams closed |
| `--end-overlap` reload | {K2, K1} → {K2} | the K1 streams closed |

**Equivalence without retiring keys (worded exactly; m9 of the second review).** Held and
accepted sets are both {primary}.
- **For every stream registered before the swap,** this decides what today's code decides.
  Every such stream holds the name's previous primary: any earlier re-key closed the others at
  its own swap, and D16 makes that true across the attribute-to-register race. So a primary
  change closes them all, as today.
- **The one difference is an improvement.** A stream that registered on the **new** key in the
  window between the swap's `Store` and its walk (it loaded the new set inside `liveMu`, §4.3)
  is now kept. Today's code closes it needlessly, because its rule is "the key changed, close
  every stream of the name".
- **Measured.** The reviewer overlaid this rule into today's code, and the whole `mtglib` suite
  passed.

**The `newSet` judgment at `now` guards only names whose held keys changed.**
`buildSecretSetAt` has already dropped every entry expired at `now`, so for a set built by this
swap at the same `now`, held and accepted are equal. The per-stream check against the accepted
set therefore matters for names the fast path does not skip; a name whose held keys are equal is
skipped before it. (Revision 4, Task 5's review: the earlier wording claimed correctness for a
set built earlier, which the fast path does not give; no caller can hand such a set.)

Streams are snapshotted under `liveMu` and closed outside it, as today. The function returns
how many it closed per name, for logging.

### 4.2 The expiry sweep (D11)

`p.expireRetiring()` runs from the maintenance loop's 5 s `sweep` case, before
`closeDeniedConns`:

```
set := p.secrets.Load(); if set.retiringNext.IsZero() { return }          // one load + compare when none
now := p.rotation.Now(); if now.Before(set.retiringNext) { return }
if !p.reloadMu.TryLock() { return }        // a reload holds it: retry on the next tick
defer p.reloadMu.Unlock()
set = p.secrets.Load(); if set.retiringNext.IsZero() || now.Before(set.retiringNext) { return }
p.swapSecretConfigLocked(set.toConfig())   // the build at now drops expired entries; their held keys
                                           // leave the set, so closeStaleConns closes their streams
                                           // (§4.1); the change is logged (§6.3)
```

**`TryLock`, not `Lock` (m3 of the review).** `ReloadSecrets` holds `reloadMu` across a file
read and parse, and an API mutation holds it too. Waiting behind one would stall the same
maintenance goroutine's `closeDeniedConns`, quota rollover and usage flush. A missed tick
retries 5 s later. If the holder swaps, it rebuilds at its own `now`, which drops the expired
entry and closes its streams (§4.1): the reload does the sweep's work. If the holder fails
without swapping, the close moves one tick later. That repeats for as long as every tick
collides with such a holder, for example a script POSTing `/reload` in a tight loop against a
file that does not parse (m11 of the second review). So the delay is **one tick per collision,
not a fixed bound**. Admission stays exact throughout, because the doors and D16 check `until`
themselves. Only streams already open wait.

- The expiry swap rebuilds from the **current** set, so API overrides survive it. The lock
  order is `reloadMu` → `liveMu` → `tableMu`, as for every swap.
- The swap cannot be refused: retiring entries never count toward `SecretsCanFront`, and the
  primaries are unchanged.
- One swap happens per distinct expiry instant. At 5,000 secrets the rebuild costs about
  10,000 SHA-256 blocks of pad precomputation (about 3.4 ms on the bench box, from piece A's
  per-block figure). The benchmark measures it (§13).
- **Precision.** New handshakes stop at `until` exactly (§3). Live streams are closed at the
  next tick (5 s), or by any swap before it, and one tick later per collision with a reload or
  mutation that does not swap (above).
- **No extra grace.** The overlap is the grace the operator chose. A second grace would make
  the real deadline something no file states.
- **Rejected:**
  - a timer per entry: more goroutines to stop, and the 5 s sweep already exists;
  - leaving expired entries in the set until the next reload: they would cost scan slots
    indefinitely;
  - closing streams only, without a swap: same objection.

### 4.3 Registration re-checks the key (D16)

**Where the check sits is the whole of its correctness (M1′ of the second review).**
`tryRegisterConn` resolves the client address *before* it takes `liveMu` (`ip`, `key`,
`keyed`, `now`). The key re-check must **not** join that preamble. It runs **under `liveMu`,
immediately after `p.liveMu.Lock()`, before the ban re-check** and before anything the rollback
must undo. Both the set (`p.secrets.Load()`) and the stream's held key (`ctx.matchedSecretKey`,
`ctx.retiringUntil`) are read inside the critical section:

```go
beforeRegisterLockHook(ctx)            // test seam: a package-level func like registerStepHook; no-op in production
p.liveMu.Lock()
defer p.liveMu.Unlock()

// The key re-check. The Load MUST stay below the Lock: a set read before it can be one a swap
// replaced while this stream waited on liveMu -- and that swap's walk ran exactly then.
cur := p.secrets.Load()
if cur != ctx.attrSet || !ctx.retiringUntil.IsZero() {   // pointer compare in the common case
    if !cur.accepts(ctx.secretName, ctx.matchedSecretKey, p.rotation.Now()) {
        return refuse(DenyKeyRevoked)                    // nothing taken yet: refuse undoes nothing
    }
}
// ... then the ban re-check, the cap, the ledger, the table entry, the registration, as today.
```

`accepts` does a binary search for the name, compares the primary key, then checks the name's
`retiringOf` entries (key equal and `now < until`).

**Why it has to be inside.** A swap stores its set **before** it takes `liveMu` to walk
`liveConns`. If the stream loads the set under `liveMu`, it is either registered before the
walk (and judged by `closeStaleConns`), or it takes the lock after the walk and loads the set
the swap stored, which no longer accepts the key. Loaded before the lock, it could hold a set
the swap has since replaced. Its `Lock()` would then return right after the walk it waited on,
and it would register a just-expired or just-removed key. That stream would live until its
client hangs up: no later sweep looks at a name whose set holds no retiring entry, and later
swaps skip the name.

This closes the new race (a retiring key that expires, or is removed, between `attribute` and
registration). It **also closes the existing race** for a plain re-key described under "Where
things stand", which is a behaviour change. It can only refuse a connection whose key the set
no longer accepts.

**Tested with seams, never by hammering.**
- **L5:** `afterAttributeHook` runs a swap before registration starts.
- **L5b:** the new `beforeRegisterLockHook`, called immediately before `p.liveMu.Lock()`, runs
  a **complete** swap at the one point where the two placements differ. A Load above the Lock
  passes L5 and fails L5b.

**Order against piece B's contract.** The ban re-check stops being the first step:
- the key re-check now precedes it, so a revoked key arriving from a banned place is refused
  and logged as `key_revoked`, not `banned`;
- the ban re-check still precedes the cap, the address limit and the ledger, which is what
  `TestTheReCheckIsTheFirstStep` asserts;
- that test is renamed (`TestTheBanReCheckPrecedesTheLimits`) with its assertions unchanged,
  and the comment at `proxy_serve.go:490` is updated (task 0).

`ctx.attrSet` is cleared once registration passes, so a long-lived stream does not pin a whole
old set (candidates and pad states) for hours. `matchedSecretKey` still points into the key
array of the set it was attributed from, as it does today.

`DenyKeyRevoked` (`String() == "key_revoked"`) is a new internal `DenyReason`. Its
`countAdmissionRefusal` case only logs: no counter and no event, as for bans. On the FakeTLS
door it is a close after the server's flight, like an ip-limit refusal. On the obfuscated door
it takes `denyObfuscated`.

**Alternative rejected:** re-checking only streams on a retiring key. That leaves the existing
re-key race open. The cost of covering everyone is one atomic load and one pointer compare per
admission, inside `liveMu`.

**The cost to the existing tests (m2 of the second review, measured by the reviewer).** With
this check in place, **37 existing `mtglib` tests fail**, and some subtests pass only
vacuously.
- **Why they fail.** Their helpers register hand-built streams without `attribute()`:
  `registerFakeStream`, `denyProbe.stream`, the ban and cap probes, and others. So `attrSet`
  and `matchedSecretKey` are nil and the check refuses them.
- **Which pass vacuously.** In `TestProxyReloadSecrets`, "added secret … disturbs nothing" and
  the alice half of "removed secret …" pass only because `registerFakeStream` ignores the
  result of `tryRegisterConn`, so the stream is never registered.
- **The fix is task 0 (§15).** It comes before every engine task: the helpers attribute
  through the stored set and register for real.

### 4.4 What else applies to both keys

The name is the unit of everything that already exists, so all of it covers the old and the new
key alike:
- quota (one counter), speed buckets, expiry/disabled (`closeDeniedConns`);
- ip-limit, client-conns and the per-address table (by name and address);
- bans (`banned(name, key)`), kick (by name and address) and hints (by name);
- the usage-state file (keyed by name; untouched);
- `/stats` users (keyed by name; no new key).

A rotation keeps the name, so it keeps the name's bans, entries and counters, exactly as a
re-key does today.

## 5. The management API (D17, D18)

### 5.1 Mutations keep the file's grants

| Call | Retiring entries afterwards |
|---|---|
| `POST /reload` | exactly the file's usable entries: `ReloadSecrets` never merges, and a nil list means "none" |
| `PUT /secrets` (the handler's `replaceSecretsKeepingRetiring`) | the current entries of every name the PUT keeps, copied in **under `reloadMu`** from the set as it is then; entries of names the PUT drops go with them |
| `ReplaceSecrets(cfg)` (library) | exactly `cfg.Retiring`, nil meaning none, as everywhere (§2.1) |
| `POST /secrets` (`PutSecret`) | the name's entries are kept; if the new primary equals one of them, that entry is dropped (the primary wins, rule 6 at engine level); a new primary never becomes a retiring entry |
| `DELETE /secrets/{name}` | the name's entries go (`forget`) |
| `PUT`/`DELETE /adtag` | kept (via `toConfig`) |

**Why PUT keeps them, when POST clears limits that are not sent.** The API cannot express a
retiring entry (D18). An absent field can therefore only mean "this request is not about
rotation", not "clear it". If PUT cleared them, every rotation-unaware client (the panel
today) would end every overlap as a side effect. The next restart would then grant them again
from the file, a kill-then-revive the operator never asked for.

**Why one meaning for nil, and an unexported merge (m6 of the review).** The keep-merge is an
unexported method beside `ReplaceSecrets`, used by `handlePutSecrets` and nothing else. It
takes `reloadMu`, copies the current set's entries for the kept names into `cfg.Retiring`, and
calls `swapSecretConfigLocked`.

Revision 1 instead overloaded `cfg.Retiring == nil` to mean "keep" inside the exported
`ReplaceSecrets` and "none" in `ReloadSecrets`. Every library caller that built
`SecretConfig{Secrets: …}` would then have kept entries without knowing.

**For embedders, said once.** A library `ReplaceSecrets` with a nil `Retiring` ends every
overlap until the next reload of the file grants them again. That is a kill-then-revive, but
within the operator's own grant, so it is no R0 breach. The field's doc comment says so.

The merge happens under `reloadMu`, against the set as it is at that moment. A PUT therefore
cannot re-add an entry that a reload or the expiry sweep removed after the handler read the
body, and the build re-applies rule 2 on the rotation clock in any case. A panel re-key stays
immediate: the PUT's old primary is gone, and it never becomes a retiring entry.

**A revert by `POST /secrets`** (re-keying the name back onto its retiring key K1) is the one
API call that makes the leaked key the primary on purpose. The entry is dropped (rule 6) and
the new key's streams are closed. It lasts until the next reload returns to the file. It is
listed in the invariant table and documented in Multi-User-and-API, because it is the only way
an operator can bring a leaked key back by hand.

### 5.2 No `POST /secrets/{name}/rotate`, and no write field (D18)

**A rotate route** would set a new primary that the file does not hold. The next reload or
restart reads the file and **makes the leaked key the primary again**, while the new link
already handed out dies. That breaks R0 directly. The only fix is for the proxy to write its
config file, which it never does: in panel deployments the panel owns that file and would
overwrite it.

**A write field** (a `retiring` array on PUT/POST) would be harmless to lose, since a lost
grant kills. It is still deferred. It needs a feature-gated strict field and absent-field
semantics that clash with POST's "absent clears" rule. It would also make the API a second way
to state something the file is the authority on, which an operator auditing a leak should be
able to read in one place.

**An in-memory "end the overlap now"** would be undone by the next reload of the unchanged file,
which would grant the key again until `until`. That kill-then-revive is the surprise R0
forbids. The CLI's `--end-overlap` plus a reload does it durably in seconds.

### 5.3 Read-only view (D19, D20, D31)

Four scalars go into **the existing user object** of `GET /stats` (`UserStatsJSON`) and into
`SecretInfo` (`GET /secrets`, `GET /secrets/{name}`). They are never a new key under `users`,
all are `omitempty`, all are absent for a name that has no retiring key and never had a
retiring admission, and none is an address (not gated):

| Field | Meaning |
|---|---|
| `retiring_keys` (int) | unexpired retiring keys the name accepts now |
| `retiring_until` (time, UTC) | the latest `until` among them: when every old link of the name stops working |
| `retiring_connections` (int) | live streams of the name whose key is **not** the name's current primary |
| `retiring_last_seen` (time) | the last admission under a retiring key; reported only while `retiring_keys > 0` |

- **`retiring_connections` is computed at read time (D20).** For names with `retiringOf`
  entries only, `liveMu` is held and each stream's `matchedSecretKey` is compared with the
  current primary. It is not an admission flag. Right after a rotation, every old-link stream
  was admitted as the primary, so a flag would read 0 exactly when the operator is watching
  the number fall.
- **`retiring_last_seen` (D31)** is an `atomic.Int64` on `secretStats`, stamped in `admit` when
  `ctx.retiringUntil` is set. It answers "has anyone used the old link lately".
  **Reset (revision 4, Task 7's review):** the stamp is cleared when a name gets its FIRST
  unexpired retiring entry in a new set (it had none in the set being replaced), so a second
  rotation never shows the previous overlap's last admission and invites an early
  `--end-overlap`. The reset runs in the swap between the build and the `Swap` of the new set
  (not after it: an admission through the new set's entry must not be wiped).
- **Feature string:** `secret-rotation`, inserted sorted between `secret-read` and
  `secrets-api`. It means that `[[retiring-secret]]` is honoured, the four fields may appear,
  and the binary has `rotate-secret`. The pinned lists in `proxy_stats_features_test.go` are
  edited deliberately.
- **Rejected:**
  - a per-entry list (`retiring: [{until, connections}]`): more surface, and the entries are
    already distinguishable by `until`;
  - a key fingerprint: no need, and a truncated hash of key material is still something to
    leak.
  - No key material, ever (D21).

## 6. Observability and secrecy (D21)

### 6.1 Never printed

Retiring values never appear in: API responses, `/stats`, any log line, any error (config,
reload, the 500 body of `/reload`, CLI), `Config.String()`, `access` output, or `rotate-secret`
output. The one exception is the file itself.

The config path parses `secret` itself (§1.1) with value-free messages and never surfaces
`Secret.Set`'s error text. A test pins this (§12, C8): it collects every log line, error string
and HTTP body during a scripted rotation and asserts that neither the hex nor the base64
spelling of the retiring value, nor its key, appears anywhere.

**The parser's error, printed safely (m13 of the second review, verified by overlay).**
- go-toml's `DecodeError.Error()` (`"toml: " + message`) never contained the document's bytes
  in the reviewer's tests: the scalar shape holding an `ee…` value, a duplicate `secret` key,
  an unterminated string. Neither did `config.Parse`'s `%w`-wrapped error.
- `DecodeError.String()`, the human form with the offending line as context (`errors.go:76`),
  **contained the value every time**.
- So wherever this piece prints "the parser's own error" (`run --check`, `rotate-secret` step 1,
  the `/reload` failure log), it prints the error's `Error()` text and never calls `String()` on
  a `*toml.DecodeError`. Formatting the error value with `%v`, `%s` or `%w` uses `Error()`,
  which is safe; only an explicit `String()`, or an `errors.As` into the type followed by its
  human form, is not. Nothing in `internal/` calls `String()` today. R7 and C8 pin it with a
  refused scalar-shape file whose refused line holds a secret value.

### 6.2 Logs

All lines carry `secret_name` and times; none carries a key.

| When | Level | Message | Fields |
|---|---|---|---|
| start and every swap, per entry that is new in this set | Info | `secret accepts a previous key until its overlap ends` | `secret_name`, `until` |
| an entry leaves the set because it expired: the sweep, or any reload or swap after `until`. Classified by the §6.3 diff, not by an engine drop reason | Info | `previous key of the secret is no longer accepted: overlap ended` | `secret_name`, `until`, `closed` |
| an entry leaves the set otherwise (file edit, removal) | Info | `previous key of the secret is no longer accepted` | `secret_name`, `reason`, `closed` |
| an entry leaves the set because its key is now the name's PRIMARY (the documented revert through `POST /secrets`/`PutSecret`; revision 4, Task 5's review) | Warning | `previous key of the secret is the primary again` | `secret_name`, `closed` |
| a config problem or warning | Warning | (§1.3 line) | |
| an engine drop that is not an expiry | Warning (`same_as_primary` and `duplicate`: Info) | `a retiring key was ignored` | `secret_name`, `reason` (`invalid`, `dangling`, `same_as_primary`, `duplicate`, `key_of_other_secret`, `over_cap`) |
| the wall clock is behind | Warning | §2.3 | `behind_by` |
| a refused registration | Info | `connection denied by per-user limit` | `deny_reason=key_revoked` |

Info is what `debug = true` shows, as for bans and kicks. The `/stats` fields are the
always-on view.

The `key_revoked` refusal stays at Info, like a ban's. It is the one behaviour change that
reaches deployments which never rotate (D16), so the release notes name it, its log line and
the race it closes (m11 of the review).

### 6.3 Change detection

`swapSecretConfigLocked` diffs `oldSet.retiring` with `newSet.retiring`, matching entries by
(name, key) and never logging the key, to choose the lines above. A swap that changes nothing
about rotation logs nothing about it.

**How the diff classifies an expiry (m6 of the second review).** An entry of `oldSet` that is
absent from `newSet` is logged **"overlap ended"** when its `until` ≤ the swap's `now`. That is
the same single `now` the build and `closeStaleConns` use (§4.1). Otherwise it is logged
"no longer accepted" with `reason` (`removed` from the file or by the API) — except when the
departing entry's key is the name's primary in `newSet` (a revert on purpose), which is logged
as "is the primary again" at Warning — this precedes the "overlap ended" classification, so a
reverted key is reported this way even after its `until`: the "no longer accepted" wording would tell an operator
auditing a leak the opposite of what happened. The `closed` count is the name's, and the streams
it counts are the replaced primary's.

The engine's `expired` drop reason does not reach this line. On a reload after `until`, the
config layer has already filtered the entry as inert (rule 2), so the engine is never handed it
and logs no drop. The diff is the only place that sees the entry leave. The `expired` engine
reason (§2.1) covers only an entry that expires between the reloader's read and the build. It is
logged at Info as the drop it is, and the diff then logs the same entry's "overlap ended" line
with its `closed` count.

L2b's reload-only variant asserts the line and its count.

## 7. The operator surface: `mtg-proxy rotate-secret` (D22–D26, D32)

### 7.1 Command and flags

The name parallels `generate-secret`, and the config path is the first positional argument, as
in `run`, `access` and `doctor`.

```
mtg-proxy rotate-secret <config-path> <name> --overlap <duration> [--host <hostname>]
                        [--prune] [--dry-run] [--reload] [--force]
mtg-proxy rotate-secret <config-path> <name> --end-overlap [--prune] [--dry-run] [--reload] [--force]
mtg-proxy rotate-secret <config-path> --prune [--dry-run] [--reload] [--force]
```

- **`--overlap D`** (Go duration, required for a rotation, 0 ≤ D ≤ 720h). `until = now + D`,
  in UTC, truncated to the second. `0` writes no block: an immediate re-key (the old key dies at
  the reload), with the same generation and atomic write. **It has no default (D32):** for a
  security action the grant must be stated. The refusal says: `say how long the previous key
  stays accepted: --overlap 24h, or --overlap 0 to retire it at once`.
- **`--host H`**: ee only. The new key's fronting host. Without it the host is kept. For dd or
  plain it is a refusal.
- **`--end-overlap`**: removes every `[[retiring-secret]]` block of `<name>`, expired or not.
  The previous keys die at the reload.
- **`--prune`**: removes every **expired** block, of any name. It combines with either of the
  above.
- **`--dry-run`**: prints a summary on stderr (never a diff, which would print the retiring
  value) and writes nothing. No key is generated.
- **`--reload`**: §7.5.
- **`--force`**: proceeds past the two refusals that are guesses (§7.6 and the binary
  pre-check in §7.5), never past a validation failure.
- A new block for a name that already has 4 unexpired entries is refused (`--prune` runs
  first). The tool never drops an existing grant to make room.
- **There is no `--mode` (m4 of the review).** The new key always has the current primary's
  mode. The engine supports a mode change across an overlap (D7, §3.2), but it is made by hand:
  edit `[secrets]` and write the block yourself. The documentation shows it. A `--mode` flag
  would need its own refusals (ee → dd leaving no ee secret and no `domain-fronting.host`), for
  a rare operation.
- **`default` while `[secrets]` is present is refused (m5 of the review):** `"default" is not
  served while [secrets] is present; rotate a name from [secrets]`. `GetSecrets` ignores the
  top-level `secret` then, so the block would be dropped as dangling.

### 7.2 What it generates and prints

- **Generation:** `mtglib.GenerateSecretMode(mode, host)`, with the current primary's mode and
  (ee) host, or `--host`. The new value is written in the **same encoding** as the old one
  (hex if the old text decodes as hex, base64url otherwise), so the file stays one style.
- **stdout carries exactly one line:** the new value as written to the file. It is printed
  once; scripts redirect it. Nothing else goes to stdout.
- **stderr**, for people:
  ```
  rotated "shared" in /etc/mtg-proxy/config.toml
  the previous key is accepted until 2026-10-09T09:30:00Z (24h0m0s from now)
  the running proxy does not know yet: POST /reload on its management API, or restart it
  links: mtg-proxy access /etc/mtg-proxy/config.toml
  ```
  With `[web] enabled = true` it adds:
  `WEB links of "shared" change now; the WEB transport has no overlap (see WEB-Proxy-Setup)`.
- **Nothing about the old key** is printed except its `until` (and, for `--prune` and
  `--end-overlap`, the name and `until` of each block removed).
- **No network access** except `--reload`. Links need the public address that `access`
  resolves; `rotate-secret` points to `access` rather than duplicating it.

### 7.3 Editing the text (D23)

go-toml v2 cannot re-marshal a document with its comments, and marshalling the struct would
drop every comment and reorder the file. So the edit is **surgical**: it locates byte ranges
with `github.com/pelletier/go-toml/v2/unstable` (`Parser` with `KeepComments`) and splices the
original bytes. The repo pins v2.4.3.

**What the parser gives (verified by the review).**
- Every key node and every string value node carries a `Raw` byte range: `"abc"`, `'lit'` and
  `"""abc"""` with their quotes, inside inline tables and dotted keys too.
- A key node's `Data` is the unquoted name, so the panel's `"name" = …` form resolves.
- **A `Table` or `ArrayTable` header node's own `Raw` is empty (m1 of the review).** The
  locator finds a header from its first key node's `Raw` and scans back to the `[` (or `[[`)
  that opens the line. It never indexes the header node's own range.
- A same-line trailing comment is not in the AST, which is harmless to a byte splice.

1. **Read and check.** Read the file. `config.Parse` the raw bytes; it must parse, and `Validate`
   must pass. A file today's parser refuses is refused here with the parser's own error, in its
   `Error()` form only (§6.1): the scalar shape of §1.1, or a UTF-8 BOM (`toml: invalid
   character at start of key`). Compute `GetRetiringSecrets(now)` with one fixed `now` for the
   whole run. Existing problems are warned about but do not block an urgent rotation; new ones
   do (step 5).
2. **The new primary.** Find the string node of the name's value. The full key path is the
   current table's path plus the key, so `[secrets] shared = …`, `secrets.shared = …`,
   `[secrets] "shared" = …` and `secrets = { shared = … }` all resolve. For `"default"` (only
   when `[secrets]` is empty, §7.1), the node is the top-level `secret`. Replace that node's
   `Raw` range with the new value in the original quote style (basic or literal). Multi-line
   strings are refused as an unsupported form.
3. **A new block.**
   - Inserted immediately before the `[secrets]` header line, and before the run of comment
     lines directly above that header, so a heading comment stays attached to it.
   - With no `[secrets]` header (the single-secret form, or dotted or inline secrets), it is
     appended at the end of the file, after a newline if the file lacks a final one.
   - The block carries its own `# added by mtg-proxy rotate-secret at <time>` comment **inside**
     the block, after the header.
   - Line endings follow the file (CRLF if its first line ends in CRLF). A BOM never gets this
     far (step 1).
4. **Removing a block** (`--prune`, `--end-overlap`). A block is introduced by either header
   kind: `[[retiring-secret]]`, or the single-table typo `[retiring-secret]`, which the parser
   reads as one entry (§1.1). Removed: from the start of the block's header line up to the start
   of the next header line, or to the end of the file. That end point is first walked back over
   the comment and blank lines directly above the next header, so a comment that heads the next
   table survives. A comment a person wrote inside a removed
   block goes with it (documented).
5. **Verify by re-parse (the safety net).** `config.Parse` the new bytes. Not
   `utils.ParseConfig`: its environment overlay and validation would hide or fail the diff. The
   result must equal the old parse in **every** field (`reflect.DeepEqual` on `Config`,
   `UnknownKeys` included) except two:
   - the name's primary, which must equal the generated secret;
   - the `RetiringSecrets` field, which must equal the old list minus the removed entries plus
     the new one, compared as raw (name, secret, until) triples.

   `Validate` must still pass, and `GetRetiringSecrets(now).Lines` must hold no problem or
   warning the old file did not have. Any difference means nothing is written: `internal error: the edit
   changed more than it meant to; nothing was written`. This catches every layout the splice
   mishandles, including a user appended after the block that would otherwise fall inside it
   (`UnknownKeys` would differ).

Steps 1 to 5 are pure functions over bytes, with no filesystem. That is task 9a (§15), where
the subtle bugs will be.

**Rejected:**
- **Re-marshalling:** it loses every comment and the order of the file.
- **Regex edits:** they cannot tell a commented-out line from a live one, or a key in one table
  from the same key in another.
- **Appending the block at the end of the file always:** it buries `[secrets]` under an array
  of tables, so the next user an operator appends "at the end of `[secrets]`" becomes an
  unknown key of the retiring block. The re-parse would catch that for `rotate-secret`, but not
  for a person editing afterwards.

### 7.4 Writing the file (D24)

1. **Resolve symlinks** (`filepath.EvalSymlinks`). The write, the lock and the temp file go
   next to the target, so a symlinked config is not replaced by a regular file.
2. **Writable checks.** Refuse when the file cannot be opened for writing (`the config file is
   not writable: <err>; nothing was written`), or when its directory cannot take a new file. A
   read-only config is a statement, so this is checked even where a rename would succeed.
3. **Lock** against another `rotate-secret`: create `<target>.rotate.lock` with `O_EXCL`,
   holding the pid and the start time. It is held until the run ends, including the `--reload`
   read-back, and removed on exit.
   - An existing lock is a refusal that names the file, its age and the remedy: `another
     rotate-secret holds <lock> (started <age> ago); if none is running, remove it and retry`.
     The tool never breaks a lock itself.
   - `O_EXCL` is reliable on local filesystems only; the documentation says a config on NFS is
     not protected against two concurrent runs (m7 of the review).
4. **Optimistic check** against other writers (an editor, the panel): just before the rename,
   re-read the target. If its SHA-256 differs from the bytes parsed in step 1 of §7.3, abort:
   `the file changed while rotating; nothing was written`. A small window is left between that
   read and the rename; it is documented.
5. **Write.** The temp file is `<target>.rotate-<8 random hex>.tmp`, created `0600`. Write, then
   `Sync`, then `Chmod` to the original permission bits. On Unix, when the temp's owner
   differs, `Chown` to the original uid and gid; a failure is a refusal (`run as the file's
   owner or root`), because a root-owned `0640` file would be unreadable to a proxy running as
   `mtg-proxy`. Close, `Rename` over the target, then fsync the directory on Unix (not
   possible on Windows; skipped). Any failure from creating the temp file up to the rename
   removes the temp file before exiting. Only a crash can leave it behind (§10).
6. **The only write path is this atomic one.** It never writes through the existing inode,
   and it never leaves a copy of the old file.

   **Single-file bind mounts** (the documented Docker form,
   `-v …/config.toml:/config/config.toml:ro`):
   - A rename on the host gives the path a new inode. As far as the review and this spec know
     (not tried), the container keeps the old inode until it is recreated, so a `POST /reload`
     inside it re-reads the OLD file.
   - The `--reload` read-back (§7.5) detects that and says so.
   - The documented fix is to mount the config's **directory** rather than the single file, or
     to recreate the container after a rotation.
   - Run inside a container, a `rename` onto a mount point fails (`EBUSY` or `EXDEV`). That is
     reported as `cannot replace <path>: it is a mount point (a single-file bind mount?); run
     rotate-secret on the host, and mount the config's directory into the container`. Nothing is
     written, and the temp file is removed.

   **Rejected (M3 of the review): an `--in-place` mode** writing through the inode after a
   backup copy.
   - The backup would be a second file holding every secret, with the **leaked key as the
     primary**, contradicting §11 "in no other file".
   - Restoring from it by hand would revive the leaked key.
   - The `O_TRUNC`-then-write window lets a concurrent `POST /reload` read a truncated file,
     which may parse as a smaller valid set.
   - The directory mount fixes the root cause.

### 7.5 `--reload` (D26)

- **Address.** It reads `api-bind-to` and `api-token` from the file. A host of `0.0.0.0` or
  `::` is reached at `127.0.0.1` or `::1`. A missing `api-bind-to` is a refusal before anything
  is written.
- **Before writing:** `GET /stats` only, for reachability and features. Revision 2's pre-write
  `GET /secrets/{name}` is dropped: nothing needs it now that every check compares with the
  written file (m5 of the second review).
  - An unreachable API is a refusal (the operator asked for a reload; writing without one would
    half-apply).
  - If `features` lacks `secret-rotation` (an older running binary, which would ignore the block
    and kill the old key at the reload), it refuses unless `--force`.
- **After writing:** `POST /reload`, which must answer 200. Then, for each name the run touched
  (the rotated or ended name, and every pruned name still configured), `GET /secrets/{name}`.
  **Every expected value comes from one source: the bytes just written**, parsed with
  `config.Parse` and judged with `GetRetiringSecrets(now)`, `now` read just before the GETs.
  Each check that fails is named, with its own likely causes:
  1. **Primary** (every form that names a name: rotation, `--overlap 0`, `--end-overlap`). The
     `secret` field (base64) must **parse to the same key, mode and host** as the name's
     primary **parsed from the written bytes**, which may hold hex: compare the parsed
     `Secret`s, not the strings. For a rotation that is the generated value. For
     `--end-overlap` it is whatever the file holds, so an earlier rotation written without
     `--reload`, or an API re-key since, is not a false failure. Likely causes of a mismatch:
     - a `SECRET` environment variable overriding `[secrets]`;
     - a single-file bind mount that still shows the old file (mount the directory);
     - another process that rewrote the file.
  2. **Retiring count.** `retiring_keys` (absent means 0) must equal the number of the name's
     usable entries in the written file. This is the review's "before + 1", restated so that
     `--prune`, `--end-overlap` and an entry expiring in the meantime are all counted from one
     source. Likely causes of a mismatch: the proxy's clock is ahead of this machine's (its
     high-water mark judged an entry expired), or the proxy logged a problem with the block.
  3. **Retiring end.** With a new block, `retiring_until` must be **≥ the written `until`**; it
     is not required to be equal. It is the latest `until` among the name's entries, so an
     earlier, longer overlap legitimately reports a later time (M1 of the review). Likely cause of a failure:
     the same as 2.

  **`--prune` alone** names no single name. It requires the 200, then check 2 for each pruned
  name that is still configured. A pruned name that is no longer configured has nothing to read
  back.

  The message is `the file is rotated but the proxy does not serve it: <check> differs
  (<expected> vs <reported>); likely: <causes for that check>`. It never prints a secret.
- **A failed reload:** exit non-zero with the same "the file is rotated" wording, and print
  **only the HTTP status line** of the failed `POST /reload`, never its body (m14 of the
  review). The body is the proxy's error text. The proxy itself logs only `Error()` forms
  (§6.1), but the CLI does not depend on that. The file is never rolled back: it is the truth, and a
  rollback would revive the leaked key at the next restart.
- It does not reload other processes that share the file. The documentation says to reload each
  one.

### 7.6 Refusing a panel-managed file (D25)

The panel writes `<bin>/mtproto/mtg-<id>.toml` and rewrites it from its own records on its
next change, re-sending the leaked key as the primary through both the file and `PUT /secrets`.
A rotation there would be undone, and the leaked key revived.

So the tool refuses any target whose base name matches `mtg-<digits>.toml` and whose parent
directory is named `mtproto`, unless `--force`:
`this looks like a config the Penhoon panel generates (…/mtproto/mtg-N.toml); the panel rewrites
it from its own records and would make the old key the primary again; re-key the client in the
panel instead`.

This is a guess, hence `--force`. A panel that relocates its files defeats it, and the
documentation states that rotation is unsupported on panel-managed files.

### 7.7 Exit status

0 is success, including a no-op (`--prune` with nothing to prune, or `--end-overlap` for a
name without blocks), which says so on stderr. Anything else is non-zero, and the message always
says whether the file was written.

## 8. Other readers

### 8.1 The WEB relay (D28)

**Serving.** The relay keeps serving primaries only (`orderedSecrets` is unchanged). A WEB user
of the old link loses access when the relay picks up the rotated file (about 4 s after the
write, by its watcher), **with no overlap**. The documentation says so in the rotation section
and on WEB-Proxy-Setup.

Why no overlap on WEB in this piece:
- the relay re-reads the file only when it changes, so it would need its own expiry clock;
- its profile ordinal is a public number in its logs and metrics, and a second profile under
  one name would need a naming rule;
- the transport is the newest one, with the smallest population.

The proxy, which is the authority, would refuse an expired key at its dd listener regardless.

**Recognition.** If a retiring capability fell to tier three, it would be **proxied to
`cover-upstream`**: the third-party access-log leak that tier two exists to prevent. So:
- `NewRegistry(host, secrets)` gains a sibling:
  `NewRegistryWithRetired(host, secrets, retired []mtglib.Secret)`.
- `retired` capabilities are derived from `WebSecret(retiring.Secret)` for **every
  syntactically valid** `[[retiring-secret]]` value in the file, expired or not, up to 4,096.
  They are read through a new accessor, `(*Config).RetiringValues() []mtglib.Secret`: the
  values that pass §1.3 rule 1, whatever their name or time. It returns nil after the `SECRET`
  override.
- They join the `IsAuthentic` scan only, never `Lookup`, so they get the local uncacheable 404.
- One equal to a live capability is dropped (the live one serves).
- The scan stays constant-time over both lists. **Its bound (m13 of the review):** up to 4,096
  live (`MaxProfiles`) plus 4,096 retired, so 8,192 constant-time 32-byte compares per
  recognition at the worst, about twice today's. The W tests and the relay's stats page
  (WEB-Proxy-Setup) state it.
- `profileReloader.apply` compares the retired list as well as the profiles, so a `--prune`-only
  change updates it. `Origin.SetSecrets` gains the list.
- Recognising an expired capability is harmless: whoever presents it already held that link.
  Expired ones are kept because the relay has no expiry clock, and recognising them still keeps
  the capability out of a third party's access log.
- A capability of a key that was re-keyed or removed with **no** block is tier three, as today
  (out of scope; noted in Risks).

### 8.2 `access`, `generate-secret`, `simple-run`

`access` prints primaries only, unchanged. A retiring link is never printed. `simple-run` has
no file, so it has no rotation.

### 8.3 Unknown keys and older binaries (D30)

In this binary the table, and every field of it, is known. A misspelt field (`[[retiring-secret]]
hosts = …`) is an unknown key (`retiring-secret.hosts`), logged by `run` and refused by
`--check`.

An older binary reports the table as unknown and **ignores it**, so it accepts the primary
only and the old key dies at once. That is the safe direction, and it is why `--reload`
checks `features` first.

## 9. Panel-managed deployments

**Nothing changes.**
- The panel's file has no `[[retiring-secret]]`.
- Its `PUT /secrets` bodies, the `/stats` shapes it reads (the four new fields are absent),
  the usage-state file, the asset names and every route and status code are unchanged.
- A panel re-key is immediate, as today: PUT never turns an old primary into a retiring entry.
- `run --check` over the panel's file reports nothing new.
- `TestPanelEmittedConfigIsAccepted` is untouched and stays green.

**How the panel could adopt rotation later:**
- It stores, per client, a list of `(previous secret, until)`.
- It renders one `[[retiring-secret]]` block per unexpired item, before `[secrets]`, the layout
  it already keeps.
- It applies the change with `POST /reload` instead of `PUT /secrets`, because PUT cannot carry
  retiring entries (D18). Alternatively a later piece adds a feature-gated PUT field, now that
  the semantics in §5 are fixed.
- It gates on the `secret-rotation` feature and drops expired items from its own records.

## 10. Failure modes

| Failure | Behaviour |
|---|---|
| Wall clock jumps forward | Overlaps whose `until` the jump passes end early, and the high-water mark keeps them ended. Fails safe. A Warning is logged when the wall clock is behind the mark (§2.3). |
| Wall clock steps back, same process | No effect on expiry decisions: the config layer and the engine read one high-water clock (§1.4, §2.3). |
| Wall clock steps back, then a restart | An entry may be accepted again for up to the size of the step. Mitigation: `--prune` after each overlap; NTP. Risks; the only full fix (a persisted mark) is noted in §2.3. |
| A reload arrives after `until`, before the sweep | The build drops the entry (engine reason `expired`). Its held key leaves the set, so `closeStaleConns` closes its streams in that same swap (§4.1, test L2b). |
| The file holds an expired entry | Inert forever. `doctor` counts it, `--prune` removes it. |
| Crash between the write and the reload | The running proxy serves the old primary until a reload or restart, and then the file's state. Nothing is revived. |
| Crash during the write | The rename never happened, so the old file is intact. A stale `0600` `.tmp` (holding the new content) and the lock file remain. The next run refuses on the lock, names it and gives the remedy, and the documentation says to delete both. No backup copy exists. |
| A hand edit writes `retiring-secret = "x"` | The one shape that refuses the whole file (§1.1). A reload keeps the previous set, the leaked key included if the edit also re-keyed; a start fails. `--check` and `rotate-secret` refuse with the parser's error, and the FAQ names the cause. |
| Two proxies share one file | Each applies the same absolute `until` on its own reload. `--reload` reloads one, and the documentation says to reload each. |
| Time zones | `until` is an instant; the CLI writes UTC. |
| A very long overlap | The CLI refuses over 720 h. A hand-written one is kept under `run`, bounded by its own `until`, with a Warning at every load, and `--check` refuses it. It is not dropped, because a drop judged against `now` would be undone by a later reload (P2). An overlap is a migration window, not a second permanent key, and the warning says so. |
| Many retiring keys | Capped at 4 per name and 4,096 in all. CPU is in §11. |
| A reload with a malformed block | The block is dropped with a Warning, and the rest of the file (the new primary included) is applied (D4). |
| An operator re-keys by API during an overlap, without the file | The in-memory primary changes and the retiring entries are kept (§5.1). The next reload restores the file's primary: the documented in-memory semantics of every API mutation, unchanged by this piece. |
| `rotate-secret` on a panel file | Refused unless `--force` (§7.6). |

## 11. Security analysis

**What the old key can do during the overlap.** Everything the name allows. The overlap is the
operator's explicit grant. While it lasts, holders of the leaked link:
- spend the name's quota and speed;
- occupy its ip-limit and client-conns slots. A public leak can therefore crowd out legitimate
  users for as long as the overlap lasts;
- earn hints for their addresses.

For a hostile leak (a link posted publicly and being abused), the guidance is a short overlap
or `--overlap 0`, plus bans of the abusive places. Bans apply to both keys, because a ban is by
name.

**Oracles.**
- A prober with no key sees the same thing before, during and after an overlap: fronting on
  FakeTLS, the single disposal on the obfuscated door.
- A holder of the old key, after `until`, is refused exactly as a wrong key is. The expired
  candidate is skipped before verification, so it is fronted with a wrong key's bytes and
  timing, apart from the skipped verification (about 4 µs on the bench box). After the expiry
  swap the key is simply not in the set.
- The one visible difference is the `key_revoked` close after the server's flight, and it occurs
  only in the microseconds between attribution and registration, like the existing ban
  re-check.

**Timing between a primary and a retiring match.** A retiring candidate sits after every
primary, so an unhinted old-link hello is verified after `N` primaries: about `N × 4 µs` later
on the bench box (20 ms at N = 5,000), and about 1 µs when hinted. Only the holder of that key
can observe it; it reveals that they hold a retiring key, which they know.

A no-match hello now scans `N + R` candidates, so a prober could see the unmatched latency grow
by `R × 4 µs` during an overlap: the same signal as adding `R` secrets, which is not specific to
rotation.

**After a restart** the hint cache is empty, so every old-link client pays a full scan and the
full budget charge, and under a flood can be fronted until the budget allows (it retries). The
same is true of every client after a restart; old-link clients are the last candidates scanned.

**CPU.**
- Each retiring ee key adds one candidate to every unhinted scan.
- Each retiring key adds one trial to the obfuscated loop, which has the per-IP failure limiter
  but no budget.
- The FakeTLS budget charges per candidate, so scan CPU stays bounded at the configured share;
  what grows is the cost of each scan, and so how soon the budget refuses during a flood.
- Worst case at the caps: 5,000 primaries + 4,096 retiring is about 1.8× the candidates.
- A typical rotation (`R ≤ 4`) is negligible.

**Hinted verification** is bounded at 32 (D12), which is 2× today's bound. It is reachable only
with earned hints on many names that are all mid-rotation.

**Bans during an overlap.** A ban is by (name, address), so it refuses the place on both keys
and survives the rotation (a rotation keeps the name). A kick likewise closes both keys'
streams from the place.

**The leaker inside the group** gets the new link like everyone else. Rotation does not address
that; bans and `ip-limit` do.

**At rest**, the retiring value sits in the file next to the primaries, under the file's own
permissions, which `rotate-secret` preserves. It is in no other file. The one exception: a
`rotate-secret` that crashes between creating its `0600` temp file and the rename leaves that
temp file (the new content) beside the config, and §10 and the documentation tell the operator
to delete it. No backup copy exists (M3 of the review).

## 12. Proof: tests (written first, each sabotage-checked)

Test seams:
- `RotationClock`'s `now` is injected (`NewRotationClock(fake, onBehind)`), and the same
  instance is handed to the reloader and to `ProxyOpts.RotationClock`;
- `runProxyWith`'s new `now` parameter, driven by the `run_proxy_loop_test.go` harness (m4′);
- the maintenance sweep interval (`startMaintenanceEvery`);
- `registerStepHook`, plus two new seams, both no-ops in production:
  - `afterAttributeHook`, between `attribute` and `admit`;
  - `beforeRegisterLockHook`, immediately before `tryRegisterConn` takes `liveMu` (M1′);
- address-controlled connections (`dialProxyFrom`) for hinted cases.

No wall-clock sleeps decide an outcome.

**Engine (E)**
- E1. `buildSecretSetAt` covers rules 2, 3, 5, 6, 7 and 8 at engine level, with the order and
  determinism of `retiring`, `cands` order (primaries first), `retiringCands`, `retiringNext`,
  and hosts in `hostnames` and `coverHosts`, but not `frontHost`.
- E2. With no retiring entries every new field is nil or zero. The set equals what **today's**
  builder makes, checked against a frozen copy of today's `buildSecretSet` kept in a test file
  (m10 of the second review). Comparing the new wrapper with itself would be vacuous. The fields
  compared are names, secrets, hostnames, `cands` order, `candIdx`, `candByName`, `hosted`,
  `frontHost`, ad tags and limits, over the existing candidate fixtures.
- E3. `toConfig` → `buildSecretSetAt` round-trips retiring entries.
- E4. `forget` drops them.
- E5. `RotationClock`: backwards steps never lower `Now()`, and `onBehind` fires once per
  episode and again after the episode ends and a new one starts. A nil pointer reads
  `time.Now`. **The zero value `&RotationClock{}`** neither panics nor runs backwards (m3′).
- E6. **One clock across the layers (M2; reached through `runProxyWith`, m4′):** the
  `run_proxy_loop_test.go` harness drives `runProxyWith` with a fake `now` and `POST`s
  `/reload` during an injected behind-clock episode. The reload neither passes nor accepts an
  entry the mark has passed, the config layer's expired count includes it, and the engine logs
  no `expired` drop for it. A sabotage that builds a second clock for the reloader inside
  `runProxyWith` makes the engine log that drop and the counts disagree, so the test fails.

**Doors (D)**
- D1. An ee client on a retiring key completes a real handshake. Its server flight is
  byte-identical to a primary holding the same key under deterministic noise, and the inner
  obfuscated handshake works.
- D2. The same client after `until` (injected clock) is fronted with the same bytes to the cover
  site as a wrong secret, before any sweep.
- D3. Primary-first: a primary match costs the same verification count with and without
  retiring entries.
- D4. A hinted old-link client matches in 2 hinted verifications with no scan charge, and the
  hint cap is 32.
- D4b. **ee → dd rotation, hinted (m2 of the review):** the name's new primary is dd (no
  FakeTLS candidate), and its old ee key is retiring. A returning old-link client from a hinted
  address matches its retiring position in 1 hinted verification with no scan charge.
- D5. dd and plain old keys on an obfuscated listener attribute to the right name and key
  (index mapping), and are refused after `until`.
- D6. A mode change across a rotation (old dd, new ee) serves both doors during the overlap.
- D7. A host change across a rotation: the old host passes the SNI gate during the overlap and
  is fronted after the expiry swap.

**Lifecycle (L)**
- L1. A rotation swap keeps every live old-key stream and every new-key stream open.
- L2. The expiry sweep closes exactly the old-key streams within one (test-shortened) sweep,
  through `closeStaleConns`'s held-key predicate, not through a close of its own.
- L2b. **(B1 of the review)** A `POST /reload` of the **unchanged** file after `until` and
  before any sweep closes exactly the old-key streams, and the new-key streams stay open. It
  runs in three variants:
  - sweep disabled, reload only;
  - sweep only, no reload;
  - a reload after `until` that fails to parse (the sweep's `TryLock` loses to it), then the
    sweep on the next tick.

  In every variant no K1 stream survives, and after the close the name's later swaps never
  touch the K2 streams. The reload-only variant also asserts the "overlap ended" log line, with
  the closed count, from the §6.3 diff (m6′).
- L3. An `--end-overlap` reload closes them at once.
- L4. A re-key with no overlap closes every stream registered **before** the swap (today's
  behaviour). A stream registered on the new key between the swap's `Store` and its walk is
  kept (m9′; the improvement is pinned at the same seam as L5b).
- L5. `afterAttributeHook` swaps in a set without the key, and registration refuses with
  `key_revoked`, both for a retiring key and **for a plain re-key** (the existing race,
  fixed).
- L5b. **(M1′ of the second review)** `beforeRegisterLockHook` runs a **complete** swap, from
  `Store` to the end of its walk, at the instant just before `tryRegisterConn` takes `liveMu`.
  There are two variants:
  - the swap expires the stream's retiring key (an injected clock past `until`);
  - the swap re-keys the stream's name with no overlap.

  Either way the registration must be refused `key_revoked`, and the stream must not appear in
  `liveConns`. A Load placed above the Lock passes L5 but fails L5b: that is the test's
  purpose.
- L6. A swap that does not change the name's **held** keys takes the fast path (counted by a
  test-only counter), and a swap that changes them never does, even when both sets accept the
  same keys at `now`. A name absent from the old set (held = ∅) never takes it.
- L7. Ban and kick apply to both keys. A revoked key arriving from a banned place is refused as
  `key_revoked` (the key re-check comes first).
- L8. Quota is shared by both keys.
- L9. The expiry sweep uses `TryLock`: with `reloadMu` held by the test, the sweep returns at
  once, and the maintenance loop's `closeDeniedConns` still runs on that tick.

**API (A)**
- A1. `PUT /secrets` keeps the entries of names it keeps and drops those of names it removes.
  The library's `ReplaceSecrets(cfg)` with a nil `Retiring` clears them (one meaning of nil).
- A2. `POST /secrets` re-keying onto a retiring key drops that entry, and its streams stay open
  under the now-primary key.
- A3. `DELETE` drops them.
- A4. `POST` for another name keeps all entries (`toConfig` carries them).
- A5. A PUT cannot re-add an entry a concurrent reload removed (lock seam: a reload runs in
  `beforeKeepMergeLockHook`, with `until` still ahead; the sweep alone would be masked by the
  build's rule 2 — revision 4, Task 6's review), and the merge reads the set UNDER `reloadMu`
  (A5b: a holder of `reloadMu` ends the overlap while the PUT waits for the lock).
- A6. `POST /reload` replaces them with the file's.
- A7. `/stats` and `GET /secrets/{name}` carry the four fields only when relevant, and the
  shapes stay byte-identical for a config without rotation
  (`TestStatsOmitemptyShapeUnchanged` untouched and green).
- A8. `retiring_connections` equals N right after a rotation with N live old-link streams.
- A9. The feature list is sorted and includes `secret-rotation`.

**Config (C)**
- C1. Every row of §1.3, as a problem, a warning or inert, with value-free messages.
- C2. `until` as a quoted string, an offset date-time, a local date-time (problem), a date
  (problem) and an integer (problem, not a parse failure).
- C3. A wrong-typed `secret` or `name` is a problem, not a parse failure.
- C4. `Validate()` never fails because of retiring entries.
- C5. `run --check` refuses problems and accepts inert entries.
- C6. The env `SECRET` clears them.
- C7. `Config.String()` redacts them and is byte-identical without the table.
- C8. **Leak sweep:** a scripted rotation (CLI, reload, API reads, a refused reload, problem
  lines, `/reload` 500 bodies, debug logs) never shows the retiring value in any spelling. It
  includes a refused scalar-shape file whose refused line holds a secret value, run through
  `run --check`, a `POST /reload` and `rotate-secret` (m13′).
- C9. **P1:** a seeded generator of files and times asserts that `--check` accepted at *t*
  implies accepted at *t′ > t*.
- C10. The panel-emitted config yields no unknown keys and no problems.
- C11. An unknown field inside the block is an unknown key.
- C12. **P2, the dual:** the same generator asserts that an entry `run` does not accept at *t*
  (its key absent from the usable list) is not accepted at any *t′ > t*. A high-water clock is
  injected, so expiry follows `now`.
- C13. **Named sequence, rule 4:** a block with `until` 721 h away is kept with a warning now,
  still kept an hour later, and refused by `--check` now but not an hour later.
- C14. **Named sequence, rule 5:** alice (until T1) and bob (until T2 > T1) share a retiring
  key. Both are dropped before T1, and bob's entry is **still dropped after T1** when the file
  is re-read.
- C15. **Shapes (M4 of the review):** a single `[retiring-secret]` table decodes as one usable
  entry with no unknown key, and does not block the load. `retiring-secret = "x"` is a parse
  error of the whole file: `run` refuses to start, a reload keeps the previous set, and
  `--check` and `rotate-secret` print the parser's error.
- C16. A retiring line fails `doctor`'s verdict, as an unknown key does; expired entries alone
  do not (m8 of the review).

**CLI (R)**
- R1. Rotation on a corpus of layouts:
  - the example config;
  - the panel's emitted layout, with quoted keys (with `--force`);
  - dotted and inline `[secrets]`;
  - the single top-level `secret`;
  - CRLF line endings;
  - no final newline;
  - comments above `[secrets]`;
  - existing `[[retiring-secret]]` blocks, and a single-table `[retiring-secret]` typo block.

  Each case checks the output bytes against a golden file and passes the re-parse diff. A
  BOM-prefixed file and the scalar `retiring-secret = "x"` are refused at step 1 with the
  parser's error, and nothing is written.
- R2. An injected bad splice (a test seam) is caught by the verification, and the file is
  byte-identical afterwards.
- R3. `--prune` and `--end-overlap` keep a comment that heads the next table.
- R4. The lock refuses a concurrent run, naming the lock file and the remedy. A changed file
  aborts before the rename.
- R5. Permissions are preserved; a non-writable file is refused; a symlink target is written
  in place of the link.
- R6. A failed rename (a test seam that returns `EBUSY`) writes nothing, removes the temp file,
  and prints the mount-point message. **No other file holding the old content exists after any
  run, successful or not** (the directory listing is compared).
- R7. stdout is exactly one line, the new value. **stderr never contains the old value**, in
  every message the tool can print, including:
  - the lock refusal and the hash-mismatch abort;
  - every `--reload` error, which prints only the HTTP status line of a failed `POST /reload`
    and never its body (m14 of the review; tested with a proxy whose 500 body contains the old
    value);
  - the step-1 refusal of a scalar-shape file whose refused line holds a secret value, which
    prints the parser error's `Error()` form only (m13′).
- R8. `--dry-run` writes nothing and generates no key.
- R9. `--overlap` is required; the 720 h bound holds; the 5th entry is refused; `--host` with dd
  is refused; `default` while `[secrets]` is present is refused.
- R10. `--reload` against a test proxy:
  - the feature pre-check (refused without `secret-rotation` unless `--force`);
  - the reload, and the read-back's three checks, each with its own mismatch message;
  - **a second rotation inside a longer earlier overlap passes** (`retiring_until` is later
    than the written `until`, and `retiring_keys` is 2) (M1 of the review);
  - `--overlap 0` and `--end-overlap` count correctly;
  - **`--end-overlap` after an earlier rotation written without `--reload`** passes check 1,
    because the expected primary comes from the written file (m5′);
  - **`--prune` alone** passes on the 200 and check 2 for each pruned name still configured
    (m5′);
  - the unreachable-API refusal before writing.
- R11. The panel-path heuristic refuses, and `--force` passes it.

**WEB relay (W)**
- W1. A retiring capability (expired or not) gets the local 404 and never reaches a recording
  cover upstream.
- W2. It never serves the bridge.
- W3. A retiring-only file change does not reload the profiles, but does update the retired
  list.
- W4. A collision with a live capability keeps the live one.
- W5. With 4,096 live and 4,096 retired capabilities, the recognition scan visits all 8,192
  whichever one matches (constant time; the bound is asserted).

**Sabotage list.** Each test above fails when its behaviour is removed:
- put retiring candidates before primaries;
- forget to try a hinted name's retiring keys;
- drop the admission expiry check;
- drop the sweep;
- make `closeStaleConns` key-blind (close all on a primary change) or name-only on removal;
- judge the fast path's sets at `now` instead of by what they hold (L2b and L2 fail);
- close expired-key streams in `expireRetiring` itself and leave `closeStaleConns` clock-judged
  (L2b's reload-only variant fails);
- build a second clock for the reloader in `runProxyWith` (E6 fails);
- load the set in `tryRegisterConn` before taking `liveMu` (L5b fails);
- leave a test helper registering a stream without a key, or ignoring `tryRegisterConn`'s
  result (task 0's enumeration command lists it again);
- print the parser's human form (`DecodeError.String()`) anywhere (C8 and R7 fail);
- classify "overlap ended" by an engine drop reason instead of the §6.3 diff (L2b's
  reload-only variant fails);
- compare `buildSecretSet` with itself instead of with today's frozen copy (E2 becomes
  vacuous; the review's own sabotage of the no-retiring set then survives);
- have the sweep `Lock` instead of `TryLock` (L9 fails);
- skip a name's retiring positions when its primary has no FakeTLS candidate (D4b fails);
- require `retiring_until` to equal the written `until` in the read-back (R10's second-rotation
  case fails);
- print the `/reload` error body (R7 fails);
- remove the registration re-check;
- send the server flight with the primary's key;
- let the clock follow the wall clock backwards;
- have PUT drop retiring entries, or keep a removed name's;
- leave `Retiring` out of `toConfig`;
- skip the env clear;
- leave the value unredacted in `Config.String()`;
- echo `Secret.Set`'s text in a problem line;
- compute `retiring_connections` from an admission flag;
- skip the re-parse verification;
- write non-atomically, or leave any copy of the old file behind (R6 fails);
- print the old value;
- let the relay `Lookup` a retired capability;
- make a problem refuse the load under `run`;
- check expired entries for dangling names;
- judge rule 5 against unexpired entries only (C14 fails);
- drop a rule-4 entry under `run` (C12 and C13 fail);
- break the fixed rule-8 order with a time-dependent tie-break (C12 fails);
- ignore the per-name cap;
- shift the obfuscated index mapping by one.

## 13. Benchmarks

Same-session A/B of the old and new binaries on the bench box (`penhoon-data`, 2 vCPU, shared,
work only under `/root/mtg-bench`). At least ten interleaved runs of each, compared with
benchstat.

| Row | Config | Bar |
|---|---|---|
| `BenchmarkDoorHandshake` ee-unpaced and dd, `secrets=1/1000/5000`, `first/last`, `hinted` (existing rows) | **no retiring entries** | no significant regression above 3% at p < 0.05; **allocs/op identical** (exact, also checked locally) |
| `BenchmarkVerify`, `BenchmarkScanBudgetReserve` | unchanged | same bar |
| new `…/secrets=N/retiring=R/old` (R ∈ {1, 100}), ee-unpaced and dd, unhinted and `hinted` | client on a retiring key | reported (no bar). Expected: unhinted ≈ a `last` row at N+R; hinted ≈ 2 verifications |
| new `BenchmarkBuildSecretSetAt`, N = 5,000, R ∈ {0, 100, 4,096} | the expiry and rotation swap | reported: bounds the cost of the expiry swap |
| new `BenchmarkCloseStaleConns`, 10,000 live streams, rotation vs unrelated change | under `liveMu` | reported: shows the fast path |

If the no-retiring rows miss their bar, the split-loop design (§3.1) is revisited before
anything else is changed.

## 14. Rollout and downgrade

- **Default behaviour is byte-identical** for every file without the table:
  - no new field is set;
  - the doors run today's loops;
  - `closeStaleConns` decides as today;
  - `/stats`, `GET /secrets` and `Config.String()` are unchanged in shape;
  - the panel contract test is untouched.

  The deliberate changes for everyone:
  - the registration re-check (D16), which only refuses a key the set no longer accepts. The
    release notes name it and its `key_revoked` log line (m11);
  - the `secret-rotation` feature string;
  - `NewProxy` building a `RotationClock` when none is passed. It reads only `time.Now` and logs
    nothing unless the wall clock steps back.
- **Downgrade:** an older binary ignores the table and kills every old key at once, which is
  safe. `run --check` on the older binary refuses the file, for whoever stages binaries.
- **Version gate for tooling:** the `secret-rotation` feature.

## 15. Task decomposition (for the plan author)

| # | Task | Depends on | Review focus |
|---|---|---|---|
| 0 | **The registration re-check, primary form (D16), and the test helpers it breaks.** `streamContext.attrSet`, set by `attribute`; `DenyKeyRevoked`; the check **under `liveMu`, right after the Lock, before the ban re-check** (§4.3); the seams `beforeRegisterLockHook` and `afterAttributeHook`; L5 and L5b (plain re-key variants). The helpers and the B contract are adapted as described under task 0 below the table | — | **the Load is inside `liveMu`** (L5b); **no test weakened**; the per-helper diff; the enumeration before and after |
| 1 | **Set building**: `RetiringSecret`, constants, `SecretConfig.Retiring` (one meaning of nil, documented on the field), `ProxyOpts.RetiringSecrets`, `buildSecretSetAt` (rules incl. the `expired` drop reason, order, candidates, hosts, cover hosts, `retiringNext`), held-key and accepted-key helpers on the set (held = ∅ for an absent name), `toConfig`/`forget`, E2 against a frozen copy of today's builder | 0 | nil-when-none; determinism; primary always wins; `frontHost` and `SecretsCanFront` untouched |
| 2 | **Rotation clock**: exported `RotationClock` (`NewRotationClock`, `Now`, `onBehind`, usable zero value), `ProxyOpts.RotationClock`, `NewProxy` resolving it before the initial build; `runProxyWith`'s `now` parameter and the plumbing that hands one instance to `makeSecretsReloader` and the proxy; E5 | 0 | monotonicity; one instance per process; no package global; zero value |
| 3 | **FakeTLS door**: split scan loop, lazy expiry, hinted positions with retiring (added whether or not the primary is a candidate) and the cap of 32, `matchAt`, `attribute`/`completeFakeTLS` carrying the matched key and `ctx.retiringUntil` | 1, 2 | byte-identical loop 1; budget arithmetic; golden server flight; ee → dd hinted |
| 4 | **Obfuscated door**: key list and index mapping, expiry | 1, 2 | allocation unchanged when none; off-by-one |
| 5 | **Lifecycle**: `closeStaleConns` with the **held-key fast path** and per-stream judgment against the new accepted set at the swap's one `now`; the re-check extended to retiring keys (`retiringUntil`, L5b expiry variant); `expireRetiring` with `TryLock` in the sweep; the §6.3 change log classified by `until ≤ now` | 3, 4 | B1: L2b in its three variants with the log line; lock order; **the Load still inside `liveMu`** |
| 6 | **API mutations**: the unexported PUT keep-merge under `reloadMu`; `ReplaceSecrets`, `PutSecret`, `DeleteSecret` and adtag paths with one meaning of nil | 1, 5 | no revival through a PUT; panel re-key immediate; the revert row |
| 7 | **Read-backs**: four fields in `/stats` and `SecretInfo`, read-time `retiring_connections`, `retiring_last_seen`, feature string | 5 | shapes unchanged without rotation; nothing under `users` |
| 8 | **Config**: tomlConfig `any` fields + normalisation (the wrong-type mark set after the JSON decode), `Config.GetRetiringSecrets(now) RetiringReport`, problems/warnings, `--check`, doctor (lines fail the verdict), env clear, `String()` redaction, the reloader on the shared clock and E6 through the `runProxyWith` harness, the shape facts (C15), `Error()`-only parser messages | 1, 2 | value-free messages; P1 and P2; `Validate` untouched; no field/method clash; E6 sees `runProxyWith`'s wiring |
| 9a | **CLI edit, pure**: unstable-parser locator (header from the key node's range), splice rules for both header kinds, re-parse verification, the corpus and golden files, the dry-run summary | 8 | the corpus; verification cannot be bypassed; no filesystem in this task |
| 9b | **CLI I/O**: lock (with remedy), hash check, atomic write, permissions and owner, symlinks, the mount-point refusal, panel heuristic, the `default` refusal, flags and output | 9a | never prints the old value; never leaves a copy of the old file |
| 10 | **CLI `--reload`**: the `GET /stats` pre-check, the reload, the after-reads for every touched name, the three checks against the written file, `--prune` alone, status-line-only errors | 7, 9b | refusal before writing; never rolls the file back; M1's second-rotation case; m5's two cases |
| 11 | **WEB relay**: retired capabilities in tier two, registry and reload compare, the 8,192 bound | 8 | constant-time scan; never `Lookup` |
| 12 | **Docs and benchmarks**: example config, wiki (Configuration, Multi-User-and-API, Security, Monitoring, WEB-Proxy-Setup, Installation, FAQ, Home table), README, release notes; bench rows and the box A/B | all | every claim matches the code; the bar met |

**Order.** Task 0 comes first, alone. Then:
- Tasks 1 and 2 can run in parallel. They touch the same `ProxyOpts` struct, but different
  fields; whichever lands second rebases.
- Tasks 3 and 4 can run in parallel after 1 and 2.
- Task 8 can start after 1 and 2.
- Task 9a follows 8, and 9b follows 9a.

**Task 0 in detail (m2 of the second review; the reviewer measured the breakage).**
- **Why first.** The D16 check refuses every stream that registers without a key. With the
  check in place and today's helpers, **37 existing `mtglib` tests fail**, and some subtests
  pass only vacuously. Every later task's red/green signal depends on the suite being honest
  first.
- **Enumerate, before changing any helper.** Add the check with the helpers untouched, then
  run `go test ./mtglib/ -count=1 -json`. Write the output to the task's directory under
  `.superpowers/` and list every event with `"Action":"fail"` and a `"Test"` field. Record
  that list, about 37 names, in the task report.
  - The reviewer's examples: `TestProxyReloadSecrets`, `TestTheReCheckIsTheFirstStep`,
    `TestCloseDeniedConns`, `TestExpiryEndsALiveSessionOnTheClock`,
    `TestMaintenanceRunsWithoutAUsageFile`, and most of the client-table, ban and client-conns
    tests.
  - The same command is the task's exit check: after the helper changes it lists nothing, and
    `go test -race ./...` is green.
- **Adapt the helpers, never the assertions.**
  - `registerFakeStream`, `denyProbe.stream`, `capStream`, the ban probes and every other
    helper that hand-builds a stream attribute it through the stored set: `matchedSecretKey`
    is the set's key for the name, and `attrSet` is `p.secrets.Load()`.
  - `registerFakeStream` stops ignoring `tryRegisterConn`'s result and requires `DenyNone`.
- **No test may be weakened.**
  - No assertion is removed or loosened. No subtest is deleted, skipped or made conditional.
    No expected `DenyReason` changes.
  - The subtests that passed vacuously (in `TestProxyReloadSecrets`, "added secret … disturbs
    nothing" and the alice half of "removed secret …") must now register for real and pass. If
    one fails once it is honest, that is a finding, reported, never patched over.
  - The one rename is `TestTheReCheckIsTheFirstStep` → `TestTheBanReCheckPrecedesTheLimits`,
    with its assertions byte-identical. The key re-check now precedes the ban re-check; the ban
    re-check still precedes the cap and the limit, which is what the test asserts. The comment
    at `proxy_serve.go:490` is updated to match.

## Docs to update

- **`example.config.toml`**: a commented `[[retiring-secret]]` block before `[secrets]`, with
  the placement rule and the CLI.
- **Configuration.md**: the table, problems vs warnings vs inert, `--check`, `--prune`, the one
  blocking shape, the BOM refusal, a mode change by hand.
- **Multi-User-and-API.md**:
  - "Kick, ban or re-key" gains a "rotate" row and replaces "Rotation … is not part of this
    release" with a section on rotation: the CLI, the state machine, what mutations do to
    retiring keys, the four fields;
  - "What a mutation does to live connections" gains the per-stream rule;
  - "Mutations are in-memory only" gains the D17/D18 reasoning and the revert row (a
    `POST /secrets` back onto the retiring key makes the leaked key primary until the next
    reload).
- **Security.md**: the overlap as a grant, crowding out ip-limit slots, the guidance for
  `--overlap 0`, oracles and timing, the restart/clock residual risk; and replace the line
  "Rotation with an overlap period, which would let … is not …".
- **Monitoring.md**: the four fields and the log lines.
- **WEB-Proxy-Setup.md**: no overlap on WEB; old capabilities answered locally; the
  8,192-compare bound.
- **Installation.md** (Docker): to rotate, mount the config's directory rather than the single
  file, or recreate the container after a rotation; a config on NFS is not protected against
  two concurrent `rotate-secret` runs.
- **FAQ.md**: "how do I retire a leaked link"; "`run` refuses the file after I edited a rotation
  block" (the table's shape, §1.1).
- **Home.md** feature table and the README feature list.
- **Release notes**: the feature, and the `key_revoked` refusal that reaches every deployment
  (D16).

## Not in this piece

- An API write path (a `retiring` field on PUT/POST);
- an overlap on the WEB transport;
- SIGHUP for `run`;
- per-key counters;
- new events or Prometheus/statsd metrics (the four `/stats` fields are the whole view);
- a rotation UI or adoption in the panel;
- automatic pruning of the file by the proxy (it never writes the file);
- `doctor` checks beyond the problem list and the expired count;
- a `--mode` flag (a mode change is a hand edit) and an `--in-place` write mode;
- persisting the high-water mark (the one fix for the restart gap, §2.3);
- tier-two recognition of keys that were re-keyed or removed without a block;
- the pre-existing echo of `[secrets]` values in `Secret.Set`'s error text.

## Risks

- **Clock step back across a restart** can accept an old key again for up to the size of the
  step. Mitigated by `--prune` and by NTP. It cannot be closed without persisting the mark,
  which this piece does not do (§2.3).
- **High-water poisoning.** A forward jump and its correction end early every overlap whose
  `until` the jump passed, for the rest of the process. It fails safe and is logged; a restart
  clears it.
- **A public leak during the overlap can crowd out legitimate users** (ip-limit, client-conns,
  quota). The documentation's guidance is short overlaps or `--overlap 0` plus bans.
- **go-toml `unstable`** has no compatibility promise. It is pinned by `go.mod`, and the
  re-parse verification turns any behaviour change into a refusal, never a bad write.
- **The file edit.**
  - TOCTOU between the hash check and the rename.
  - Comments inside a removed block are lost.
  - The `O_EXCL` lock is reliable on local filesystems only.
  - A single-file bind mount does not see the rename. `--reload` detects it; the
    documentation says to mount the directory.
  - All four are documented.
- **The one blocking shape.** A scalar `retiring-secret = "x"` refuses the whole file, and on a
  reload keeps the previous primary, which may be the leaked one. `--check`, `rotate-secret`
  and the FAQ surface it, and the CLI never writes it (§1.1).
- **The panel heuristic** can miss a relocated panel file. The documentation says rotation is
  unsupported there.
- **The registration re-check** changes today's behaviour in a microsecond race. Only revoked
  keys are refused.
- **CPU.** Retiring keys make every unhinted scan dearer while they exist (§11). The caps bound
  it.
- **WEB holders are cut at rotation.** The documentation says so; a follow-up could add an
  overlap there.

## Could not verify

- That a container keeps a single-file bind mount's old inode after a rename on the host, and
  that `rename` onto a bind-mount target fails with `EBUSY` or `EXDEV`. This is from general
  knowledge of Linux bind mounts, and the review did not try it either. Since revision 2 it
  only shapes a message and a piece of documentation (no `--in-place`).
- **Now verified by the reviews**, so no longer open:
  - go-toml v2.4.3's `unstable.Parser` gives exact `Raw` ranges for every string form and key
    node, but **not** for table headers (m1, handled in §7.3);
  - a single `[retiring-secret]` table decodes as one entry, and a BOM is refused;
  - `DecodeError.Error()` did not quote document text in three refused documents carrying a
    secret value, while `DecodeError.String()` did every time. §6.1 therefore prints only
    `Error()`, and the CLI still never prints a `/reload` body (m13′; first review m14);
  - D16 as specified breaks 37 existing tests through their helpers (task 0).
- Whether a per-secret ad tag issued by @MTProxybot stays valid after a key change. That is
  unchanged by this piece; it is the same question as any re-key today.
- The bench-box figures cited (about 4 µs a candidate, about 340 ns a block) come from piece A's
  spec, not remeasured.

## Decided by the agent — please audit

1. The file is the only source of retiring keys; there is no API write path at all, not even a
   harmless-to-lose PUT field (D1, D18).
2. Problems in retiring entries never block a load; `run --check` refuses them (D4). The
   alternative, refusing the file, is consistent with `[secret-limits]` but can freeze the
   leaked key as the primary.
3. `PUT /secrets` keeps retiring entries, through an unexported keep-merge in the HTTP handler,
   unlike POST's "absent clears" for limits. The library field keeps one meaning (nil is none)
   (D17).
4. Retiring candidates come after all primaries (D9). Cost: an old-link client pays a full scan
   after a restart (empty hints) and is the last scanned in a flood.
5. The registration re-check covers every stream and fixes the pre-existing re-key race (D16),
   a deliberate behaviour change. It reads the set **inside `liveMu`**, which is the condition
   its correctness rests on (second review M1′, L5b). It also moves ahead of piece B's ban
   re-check, and it costs about 37 test helpers an honest key (task 0, first).
6. Retiring ee hosts join the SNI gate and cover hosts (D7), enabling host-changing rotations.
7. A high-water rotation clock (D10), with its poisoning trade-off, made an exported
   `RotationClock` shared through `ProxyOpts`, so the config layer and the engine read one clock
   (review M2), rather than two clocks with the engine as sole authority.
8. Caps: 4 per name and 4,096 in all (drops), and 32 hinted verifications (D6, D12). A `until`
   more than 720 h away is only a **warning** under `run` (kept, bounded by its own `until`),
   because a drop judged against `now` would be reversed by a later reload, breaking P2/R0.
   `--check` and the CLI refuse it.
9. Rule 5 (cross-name key collision) is judged against every syntactically valid entry,
   **expired and dangling included**, so a dropped entry stays dropped. Cost: an expired block
   left in the file keeps blocking a later block that reuses its key under another name, until
   it is pruned.
10. `--overlap` is required, with no default; `--reload` is opt-in (D26, D32).
11. The panel-path heuristic with `--force` (D25).
12. WEB: no overlap; retiring capabilities are tier two (D28).
13. The surgical text edit with re-parse verification, rather than a TOML re-marshal (D23).
14. The four read-back scalars; `retiring_connections` is computed at read time (D19, D20).
15. Expiry closes live streams at the next 5 s tick, one tick later per collision with a
    non-swapping reload, with no extra grace (D11). The close goes through `closeStaleConns`'
    **held-key predicate** (the per-stream branch it reaches because the held sets differ), not
    through a close in the sweep (review B1). The sweep takes `reloadMu` with `TryLock`
    (review m3).
16. No SIGHUP for `run` (D27): a SIGHUP ends the process today, and changing that is not
    additive.
17. No `--in-place` write mode and no backup copy (review M3). A single-file bind-mount user
    mounts the directory instead.

## Revision notes

- **Revision 3 (2026-10-08, after the scoped re-review of revision 2: 0 blockers, 1 major,
  13 minors; verdict SOUND_WITH_FIXES).** The re-review confirmed every revision-2 disposition
  and found no failing state-table cell, given one condition. The changes:
  - **M1′, the major.** §4.3 and D16 now state that the key re-check loads the set and the
    stream's held key **inside `liveMu`**, right after the Lock and before the ban re-check,
    and never in `tryRegisterConn`'s pre-lock preamble. A new seam, `beforeRegisterLockHook`,
    and test L5b run a complete swap at the one point where the two placements differ, with a
    sabotage to match.
  - **The measured cost of D16 on today's suite** (37 failing tests, some vacuous passes) is
    recorded, and a new **task 0**, first in the decomposition, lands the primary form of the
    re-check together with the helper changes. It carries an enumeration command and the rule
    that no test is weakened. Piece B's ban re-check is no longer the first step; its test is
    renamed with its assertions unchanged.
  - **Minors (all 13), as listed in the dispositions:**
    - `GetRetiringSecrets(now)`, returning a `RetiringReport` (m1′, m7′);
    - the wrong-type mark set after the JSON decode (m8′);
    - a usable `RotationClock` zero value, and `NewProxy` resolving the clock before its initial
      build (m3′);
    - `runProxyWith`'s `now` parameter and E6 through the harness (m4′);
    - the `--reload` checks all from the written file, and `--prune` alone (m5′);
    - "overlap ended" classified by the §6.3 diff (m6′);
    - held = ∅ for an absent name, and the exact equivalence wording (m9′);
    - E2 against a frozen copy of today's builder (m10′);
    - "one tick per collision" instead of "10 s at worst" (m11′);
    - the editorial fixes (m12′);
    - the `DecodeError.String()` risk pinned and the go-toml item closed (m13′).

    An embedder note on `ReplaceSecrets` with a nil `Retiring` was added (re-review §6).
  - **Decision count:** still 32. D11 and D16 were re-worded.

- **Revision 2 (2026-10-08, after the independent adversarial review: 1 blocker, 4 majors,
  14 minors).** Every finding is listed under "Review dispositions" below. What changed:
  - **B1, the blocker.** `closeStaleConns`'s fast path compares **held-key sets** (no clock)
    instead of two accepted sets judged at `now`. Revision 1 skipped the name at the expiry
    sweep and on a reload after `until`, so the old key's live streams were never closed. Added
    an outcomes table (§4.1), test L2b in three variants, L6's stronger form, two sabotages, and
    the matching rows in the invariant table and §10.
  - **M2.** One `mtglib.RotationClock` per process, exported and shared through
    `ProxyOpts.RotationClock` with the reloader that `runProxyWith` builds before `NewProxy`.
    The behaviour during a behind-clock episode is stated (§2.3, invariant table). The engine's
    drops gain the `expired` reason. Test E6.
  - **M3.** `--in-place` and the backup copy are removed. The only write is temp, fsync,
    rename; a single-file bind mount is handled by documentation (mount the directory) and the
    `--reload` read-back.
  - **M1.** The `--reload` read-back reads before and after, checks the primary, the retiring
    count (from the written file) and `retiring_until ≥` the written `until`, with a message
    per check. R10 gains the second-rotation case.
  - **M4.** The BOM claim and corpus row are corrected (a BOM is refused). The single
    `[retiring-secret]` table is pinned as one entry (C15, and the locator handles that header).
    The scalar `retiring-secret = "x"` is stated as the one shape that blocks a load and keeps
    the previous primary, with how `--check`, `rotate-secret`, `/reload` and the FAQ surface it.
  - **Minors:**
    - header ranges (m1);
    - hints without a primary candidate (m2, D4b);
    - `TryLock` (m3, L9);
    - no `--mode` (m4);
    - the `default` refusal (m5);
    - one meaning of nil (m6);
    - the lock remedy and NFS (m7);
    - the doctor verdict (m8, C16);
    - the task split into 9a and 9b (m9);
    - `--end-overlap` and rule 8 (m10);
    - `key_revoked` in the release notes (m11);
    - persisting the mark noted as the one fix for the restart gap (m12);
    - the 8,192 bound (m13, W5);
    - status-line-only reload errors (m14, R7).
  - **Decision count:** still 32. D4, D10, D11, D15, D17, D22 and D24 were re-worded; no
    decision was added or removed.
  - Revision 3 later dropped M1's pre-write `GET /secrets/{name}` (second review m5).

- **Revision 1.1 (2026-10-08, the same day, a second advisor round).** It found that
  revision 1 broke R0 in two §1.3 rows. Revision 1 proved only P1 (`--check` is monotone); R0
  needs P2 for `run`: what is dropped from an unchanged file stays dropped. Both counterexamples
  are now named tests:
  - **Rule 4** dropped an entry whose `until` was more than 720 h away, and a reload an hour
    later accepted it. It is now a warning (kept under `run`, refused by `--check` and the CLI).
  - **Rule 5** judged collisions against unexpired entries only. When one colliding entry
    expired, a reload accepted the other. It is now judged against every syntactically valid
    entry.

  Also added: the P2 argument rule by rule (including rule 8's fixed order), tests C12 to C14
  and three sabotages. The `--reload` read-back now compares parsed keys (the API answers in
  base64, while the file may hold hex).

- **Revision 1 (2026-10-08).** Written after an advisor round that changed one decision and
  added five:
  - problems no longer refuse the load (they did in the first draft);
  - the panel-file refusal;
  - `retiring_connections` computed at read time;
  - tier-two recognition of retiring capabilities in the relay;
  - the CLI's `--in-place`, `config.Parse`-only verification, summary-only dry run and the
    `--reload` pre-check and read-back;
  - the high-water poisoning warning;
  - and the plain re-key race named as fixed.

  An independent adversarial review followed (revision 2 above). Revision 2 removed `--in-place`
  again.

## Review dispositions

### First review (revision 1.1)

The review is `.superpowers/sdd/2026-10-08-secret-rotation/spec-review.md` (verdict: BLOCKED
by B1, otherwise SOUND_WITH_FIXES). Every finding is listed with what was done and where.
Totals over the 19 findings (M4's two parts, a and b, share one count): 15 accepted, 4
modified, 0 declined.

| ID | Finding | Disposition | Where it landed |
|---|---|---|---|
| B1 | The fast path judged at `now` skips the expiry close | **accepted** (the review's held-key predicate, verbatim in substance) | §4.1 (held vs accepted sets, outcomes table), §4.2 pseudocode note, invariant table, §10, D15, tests L2/L2b/L6, sabotage list, task 5 |
| M1 | The read-back fails a second rotation inside a longer overlap | **modified**: before and after reads (revision 3 dropped the pre-write read again, m5′), a primary check and `retiring_until ≥ written`, as asked. The count is checked against the number of the name's usable entries in the written file (at the read-back's `now`) instead of `before + 1`, so `--prune`, `--end-overlap` and an expiry in between count from one source. Error text is per check | §7.5, R10, task 10, sabotage list |
| M2 | "One clock" cannot be wired as written | **accepted**, the review's second option: an exported `RotationClock` shared through `ProxyOpts.RotationClock` and handed to the reloader by `runProxyWith`. Engine drops also gain `expired`; the behind-clock behaviour is stated | D10, §1.2, §1.4, §2.1, §2.3, §6.2, invariant table, §10, E5/E6, task 2, task 8 |
| M3 | `--in-place` leaves a copy of the leaked key; `O_TRUNC` window | **accepted**: dropped, with the backup | D24, §7.1, §7.4 step 6 (with the rejection), §10, §11 (now true), R6, Risks, Not in this piece, task 9b |
| M4a | A UTF-8 BOM is refused by today's parser | **accepted** | §1.1, §7.3 steps 1 and 3, R1, Configuration docs |
| M4b | `[retiring-secret]` decodes as one entry; `retiring-secret = "x"` blocks the file | **accepted**: both stated and tested; the locator handles the single-table header; the scalar shape is the stated exception to D4, surfaced by `--check`, `rotate-secret`, `/reload` and the FAQ. Making that shape non-blocking too was considered and rejected (it would lose go-toml's strict field check inside the block) | D4, §1.1, invariant table, §7.3 step 4, §10, C15, R1, Risks, FAQ |
| m1 | A table header node's `Raw` is empty | **accepted** | §7.3 "What the parser gives", task 9a |
| m2 | Hints skip a name whose primary is no FakeTLS candidate | **accepted** | §3.1, D4b, sabotage list, task 3 |
| m3 | The sweep blocks the maintenance goroutine on `reloadMu` | **accepted** (`TryLock`) | §4.2, L9, sabotage list, task 5 |
| m4 | No `--mode` while D7 advertises mode changes | **modified**: no flag; a mode change is stated to be a hand edit and documented | D22, §7.1, Not in this piece, Configuration docs |
| m5 | `default` with `[secrets]` present would write a dangling block | **accepted** (refused) | §7.1, §7.3 step 2, R9, task 9b |
| m6 | One exported field, two nil meanings | **modified**: one meaning everywhere (nil is none); the PUT keep-merge is an unexported step of the HTTP handler rather than an exported `ReplaceSecretsKeepingRetiring` | D17, §2.1, §5.1, A1, task 6 |
| m7 | A crashed run's lock needs a remedy; `O_EXCL` on NFS | **accepted** | §7.4 step 3, R4, Risks, Installation docs |
| m8 | Retiring problems should fail the doctor's verdict | **accepted** | §1.4, C16, task 8 |
| m9 | Task 9 too large | **accepted** (9a pure, 9b I/O) | §7.3 end, §15 |
| m10 | `--end-overlap` can bring an over-cap entry back | **accepted** (one paragraph) | §1.3 after P2 |
| m11 | `key_revoked` at Info is invisible | **accepted** (kept at Info; release notes name it) | §6.2, §14, Docs to update |
| m12 | A persisted high-water file is the only fix for the restart gap | **modified**: noted as the one future fix, not done (this piece writes no new file) | §2.3, Risks, Not in this piece |
| m13 | The relay scan bound is 8,192 | **accepted** | §8.1, W5, WEB-Proxy-Setup docs |
| m14 | stderr coverage; never print the `/reload` body | **accepted** | §7.5, R7, sabotage list |

The review's state table was compared with the spec's. The two live-stream rows it marked
(B1) are now in the invariant table and §10. Its "revert by POST" row was added to the
invariant table, to §5.1 and to the Multi-User-and-API docs.

### Second review (scoped re-review of revision 2)

The re-review is `.superpowers/sdd/2026-10-08-secret-rotation/spec-rereview.md` (verdict:
SOUND_WITH_FIXES; 0 blockers, 1 major, 13 minors). Its IDs restart at m1, so they are listed
here as M1′ and m1′ to m13′, apart from the first review's IDs. Totals over these 14 findings:
**13 accepted, 1 modified, 0 declined.**

| ID | Finding | Disposition | Where it landed |
|---|---|---|---|
| M1′ | The D16 re-check must read the set inside `liveMu`; a pre-lock Load reopens the race, and no test caught it | **accepted** | §4.3 (placement, pseudocode with the Lock, why), D16, the new seam `beforeRegisterLockHook`, L5b, sabotage list, tasks 0 and 5, audit item 5 |
| m1′ | `Config.RetiringSecrets` is both a field and a method | **accepted**: the method is `GetRetiringSecrets(now)` | §1.2, §1.4, §2.3, §7.3 steps 1 and 5, §7.5, task 8 |
| m2′ | D16 makes 37 existing tests fail; some pass vacuously; B's "ban re-check first" contract moves | **modified**: adopted in full, but in a **new task 0**, first in the decomposition (the coordinator's placement), not inside task 5. The primary form of the re-check lands with it, with an enumeration command and the no-weakening rule. B's test is renamed with its assertions unchanged | §4.3 ("The cost to the existing tests", "Order against piece B's contract"), §15 task 0 and its detail, L7, sabotage list, Could not verify |
| m3′ | `RotationClock`'s zero value panics | **accepted** (a usable zero value; `NewProxy` resolves the clock before its initial build) | §2.3, E5, task 2 |
| m4′ | E6 cannot see `runProxyWith`'s wiring | **accepted** (`runProxyWith` gains `now`; E6 runs through the loop harness; the sabotage is restated) | §1.4, §12 seams, E6, sabotage list, tasks 2 and 8 |
| m5′ | `--reload` check 1 for `--end-overlap` uses the stale "before"; `--prune` alone undefined | **accepted** (every expected value comes from the written file; pre-write `GET /secrets/{name}` dropped; `--prune` alone defined) | §7.5, R10, task 10, revision 2 note |
| m6′ | "Overlap ended" cannot come from the engine's `expired` reason on the reload path | **accepted** (classified by the §6.3 diff with the swap's `now`) | §6.2 table, §6.3, L2b, sabotage list, task 5 |
| m7′ | `GetRetiringSecrets`' signature has no channel for the Info outputs | **accepted** (`RetiringReport{Usable, Lines, Expired, Notes}`) | §1.2, §1.4, §7.3, task 8 |
| m8′ | The unexported wrong-type mark cannot cross the JSON step | **accepted** (set after the decode, from the normalisation pass) | §1.1, task 8 |
| m9′ | The equivalence paragraph overstates; held(old) undefined for an absent name | **accepted** | §4.1 (held = ∅; worded equivalence), L4, L6 |
| m10′ | E2 is vacuous once `buildSecretSet` wraps the new builder | **accepted** (a frozen copy of today's builder) | E2, sabotage list, task 1 |
| m11′ | "10 s at worst" is not a bound | **accepted** ("one tick per collision") | D11, invariant table, §4.2, audit item 15 |
| m12′ | Editorial leftovers | **accepted**: duplicate §15 header removed; `--mode` gone from 9b; the parallelism note says what 1 and 2 share; L9 placed after L8; D11 named in the revision-2 note; audit item 15 says "held-key predicate" | §15, §12, Revision notes, audit list |
| m13′ | Close the go-toml item, and pin the `DecodeError.String()` risk | **accepted** | §6.1, C8, R7, sabotage list, Could not verify |

The re-review's §6 observation (a library `ReplaceSecrets` with a nil `Retiring` ends overlaps
until the next reload) is stated for embedders in §5.1. It was not a numbered finding.
