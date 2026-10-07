# Rotation of a shared secret with an overlap period — design

Date: 2026-10-08 (revision 1, after one advisor round; an independent adversarial review is
next). Status: draft for review, under delegation. Piece R of the shared-secret program (A
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
| `POST /reload` of an unchanged file during the overlap | the file's (the new key) | accepted until `until` |
| reload or restart after `until` | the file's | not accepted: an expired entry is inert (D11) |
| restart during the overlap | the file's | accepted until `until` |
| crash after the file write, before any reload | at restart, the file's (new) | per the file |
| crash during the write | the old file is intact (atomic rename) | per the old file: no rotation happened |
| panel rewrites its file (no `[[retiring-secret]]`) and restarts | the panel's | not accepted |
| `PUT /secrets` (panel or operator) | the PUT's | in-memory entries of names the PUT keeps survive; none are created (D17) |
| an older binary reads the file | the file's | not accepted: the table is an unknown key (logged; `--check` refuses) |
| the wall clock steps back after `until`, same process | — | not accepted: high-water clock (D10) |
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
  a warning, which kills that old key. `run --check` refuses the file.
- **D5** Problems and inert conditions are separated, and the time-dependent checks look only
  at unexpired entries. A file `run --check` accepts at time *t* is therefore accepted at every
  later time.
- **D6** Caps: 4 per name, 4,096 in all, and `until` no more than 720 h after the load.
- **D7** A retiring value may have any mode and any host. Door behaviour follows the value's own
  mode.
- **D8** Key uniqueness: the primary always wins. A cross-name collision is a problem.
- **D9** Retiring FakeTLS candidates come after every primary candidate. Every new field is nil
  when there is no retiring key.
- **D10** Expiry is judged by a high-water wall clock.
- **D11** Expiry is exact at admission and within one 5 s sweep for live streams, with no extra
  grace.
- **D12** A hinted name tries its primary, then its retiring keys. At most 32 hinted
  verifications per hello.
- **D13** The budget is unchanged. Retiring candidates are charged like any other candidate.
- **D14** The matched key, not the name's primary, travels to the server's flight and to the
  inner handshake.
- **D15** `closeStaleConns` decides per stream, by the stream's own key.
- **D16** Registration re-checks the key, which also closes the pre-existing re-key race.
- **D17** API mutations preserve retiring entries. A removal drops them, and a re-key onto a
  retiring key drops that entry.
- **D18** No `rotate` route and no write field.
- **D19** Read-only view: four scalars inside the existing objects, and the feature string
  `secret-rotation`.
- **D20** `retiring_connections` is computed at read time from each stream's key.
- **D21** Key material never appears in logs, errors, API responses or `Config.String()`.
- **D22** A new CLI command, `rotate-secret`.
- **D23** A surgical text edit, verified by a re-parse diff.
- **D24** Atomic write discipline.
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
failure to parse the file. A wrong shape for the table itself (for example
`retiring-secret = "x"`) is still a parse error, as it is for every other table.

`Config` gains `RetiringSecrets []ConfigRetiringSecret json:"retiringSecrets,omitempty"`.
`ConfigRetiringSecret` has `Name`, `Secret` and `Until` as raw strings plus an unexported
wrong-type mark. The values are **not** parsed during the JSON decode, because a
`TextUnmarshaler` error would carry no index and might echo the value. `omitempty` keeps
`Config.String()` byte-identical for every file without the table, including the panel's.

### 1.2 Reading it: `(*Config).RetiringSecrets(now) ([]mtglib.RetiringSecret, []string)`

This returns the usable entries and the problems. It is pure (no logging, no state) and takes
`now`, so a test injects the clock. Every caller uses it: the `run` start-up, the reloader,
`run --check`, `doctor` and `rotate-secret`. `Validate()` does **not** call it (D4), so
`web-relay`, `access` and `doctor` never fail because of a retiring entry.

### 1.3 Problems, inert entries, and why they never block a load (D4, D5)

Each entry is classified in this order.

| # | Condition | Class | Under `run` and reload | Under `run --check` |
|---|---|---|---|---|
| 1 | `name` empty or wrong type; `secret` wrong type, unparseable, or an all-zero key; `until` missing, wrong type, without an offset, or not RFC 3339 | problem (does not depend on time) | entry dropped, warning | refused |
| 2 | `until` ≤ now | **inert** (expired) | ignored; one Info summary line naming the count and suggesting `--prune` | accepted |
| 3 | `name` not a configured secret | problem | dropped, warning | refused |
| 4 | `until` > now + 720 h (`mtglib.MaxRetiringOverlap`) | problem | dropped, warning | refused |
| 5 | the key equals another name's primary key, or another name's unexpired retiring key | problem | dropped, warning (both colliding retiring entries are dropped; a primary is never touched) | refused |
| 6 | the key equals its own name's primary key | inert (the primary already accepts it) | ignored, Info | accepted |
| 7 | two unexpired entries of one name with the same key | inert duplicate | collapsed to one with the later `until`, Info | accepted |
| 8 | more than 4 unexpired entries for one name (`mtglib.MaxRetiringPerSecret`), or more than 4,096 in all (`mtglib.MaxRetiringSecrets`) | problem | keep the 4 latest `until` per name, then the 4,096 latest overall (ties broken by name, then key bytes); drop the rest, warning | refused |

**Why a problem drops the entry instead of refusing the file.** A refused reload keeps the
previous set. Take a hand edit that re-keys `[secrets]` and adds a retiring block with a typo
in `until`. Refusing it would leave the **leaked key as the primary** and the new key dead,
which is the opposite of what the operator asked for. A dangling block would also block the
removal of a user. And `Validate()` runs inside `web-relay` (at start and on every watcher
reload), `access` and `doctor`, none of which uses these entries. Dropping fails toward
*killing* the old key, which R0 permits. The cost is that users of that old link are cut
early, and the warning (at the default log level) says why. This is the same split as unknown
keys: logged by `run`, refused by `--check`.

**Why acceptance is monotone in time.**
- Rule 1 does not depend on time.
- Rules 3, 4, 5 and 8 are applied to unexpired entries only.
- Rule 4 compares `until` with `now + 720h`, and `now` only grows.
- As time passes, entries only move into rule 2.

So a file `--check` accepts at *t* is accepted at every *t′ > t*. A test pins this (§12, C9).

**Messages are value-free.** The format is `retiring-secret #<n> (name "<name>"): <reason>; the
entry is ignored and its key is not accepted`. `<n>` is the 1-based position in the file. The
reason never contains the secret. `until` is not a credential and may be echoed.

### 1.4 Wiring

- `makeSecretsReloader` adds `Retiring: usable` to the `SecretConfig` it returns, and logs each
  problem line at Warning with `warnUnknownKeys`' wording style, on start-up and on every
  reload.
- `runProxyWith` passes `ProxyOpts.RetiringSecrets` and logs the problems once.
- `checkConfig` refuses when there are unknown keys **or** retiring problems:
  `errRetiringProblems`, listing the lines.
- `doctor` lists the problem lines, plus the count of expired entries with the `--prune` hint.

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

- `SecretConfig.Retiring []RetiringSecret` and `ProxyOpts.RetiringSecrets []RetiringSecret`.
- The engine applies rules 2, 3, 5, 6, 7 and 8 again, defensively, for library callers and for
  states only the engine sees (a `POST /secrets` re-key onto a retiring key). At engine level
  every rule drops and logs; none is an error.
- The engine does not apply the 720 h cap: that is a config and CLI rule.

### 2.2 Building the set (D9)

`buildSecretSet` keeps its signature (about 40 test call sites use it) and becomes
`buildSecretSetAt(…, nil, time.Time{})`. The new function is

```go
func buildSecretSetAt(secrets map[string]Secret, perSecret map[string][AdTagLength]byte,
    global *[AdTagLength]byte, limits map[string]SecretLimits,
    retiring []RetiringSecret, now time.Time) (*secretSet, []retiringDrop)
```

`retiringDrop` is `{name string; until time.Time; reason string}`, for logging. It never holds
a key. New `secretSet` fields, **all nil or zero when no retiring entry survives**:

```go
retiring       []retiringEntry   // {nameIdx int; secret Secret; until time.Time},
                                 // sorted by (nameIdx, until desc, key bytes)
retiringOf     map[int][]int     // nameIdx -> indices into retiring
primaryCands   int               // cands[:primaryCands] are primaries; the rest are retiring ee keys
candRetiring   []int             // candRetiring[pos-primaryCands] = index into retiring
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

`Proxy.rotation *rotationClock`, built by `NewProxy` (nil-safe: a `Proxy{}` literal reads
`time.Now`):

```go
type rotationClock struct {
    now    func() time.Time   // time.Now in production; injected in tests
    mark   atomic.Int64       // the latest wall time seen, unix nanos
    behind atomic.Bool        // a warning for the current "wall clock behind" episode was logged
}
```

`read()` returns `max(now(), mark)` and advances `mark` by CAS. It is the only clock for
retiring expiry: `buildSecretSetAt`'s `now`, the door checks, the sweep, the registration
re-check and the read-backs.

- **Why.** Within a process, an NTP step backwards after `until` must not make a reload of the
  unchanged file accept the old key again (R0).
- **Fail-safe, but silent.** One forward jump followed by a correction ends every overlap early
  for the rest of the process. So `read()` logs once per episode at Warning, when the wall
  clock is more than 1 s behind `mark`:
  `the wall clock is behind the latest time seen; rotation overlaps are judged by the latest time`,
  with `behind_by`.
- **Rejected:** the monotonic clock alone. It cannot be compared with an absolute `until` read
  from a file.

## 3. The two doors

### 3.1 FakeTLS (D12, D13, D14)

```
hinted          := p.hintedPositions(ctx, parsed, set)      // per hinted name: primary, then its
                                                            // retiringCands; deduped; at most 32
pos, tried      := p.verifyHinted(parsed, set, hinted)      // a retiring position whose until has
                                                            // passed is passed over, unverified
res, …          := p.reserveScan(…, len(set.cands)-tried, …) // unchanged
pos, scanned    := p.scanCandidates(parsed, set, skip)      // loop 1 over cands[:primaryCands] is
                                                            // today's loop byte for byte; loop 2 over
                                                            // cands[primaryCands:] checks until first
m               := set.matchAt(pos)                         // {idx, key *[16]byte, retiring int}
p.completeFakeTLS(ctx, rewind, set, parsed, m)              // SendServerHello(m.key)
```

- **Expiry at the door (D11).** `now` is read lazily, once per hello and only if a retiring
  position is reached. A candidate with `until ≤ now` is never verified. A hello under an expired
  key matches nothing and is fronted with the same bytes as a wrong secret. Between `until` and
  the next sweep (at most 5 s) the expired candidate is still in `cands`, so the scan charge
  counts it: an overcharge of at most the expired count, never an undercharge.
- **Hints.** A hint is still a name, written only after the whole success path. A client
  admitted under a retiring key leaves the hint `name`, and next time is verified against the
  name's primary (a miss) and then its retiring keys, so a returning old-link client costs 2
  verifications instead of a scan.
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
if len(set.retiring) > 0 { now := p.rotation.read(); for r := range set.retiring {
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

`closeStaleConns(oldSet, newSet)` keeps its contract ("a stream whose key the new set no longer
accepts is closed") but decides it **per stream**.

For each name in `liveConns`:
- the name is absent from `newSet` → close all of its streams (as today);
- the name's **accepted-key set** (primary plus unexpired retiring keys, judged at the swap's
  `now`) is identical in `oldSet` and `newSet` → skip the name (fast path);
- otherwise, close each stream whose `matchedSecretKey` is not in the new accepted set.

Without retiring keys this decides exactly what today's code decides. Every live stream of a
name holds the name's current primary, because any re-key closed the others at its own swap;
D16 makes that true even across the attribute-to-register race. So a primary change closes all
of the name's streams, as today.

With an overlap, a rotation (`{K1}` → `{K2, K1}`) closes nothing, and the end of the overlap
(`{K2, K1}` → `{K2}`) closes exactly the K1 streams. Streams are snapshotted under `liveMu` and
closed outside it, as today. The function returns how many it closed per name, for logging.

### 4.2 The expiry sweep (D11)

`p.expireRetiring()` runs from the maintenance loop's 5 s `sweep` case, before
`closeDeniedConns`:

```
set := p.secrets.Load(); if set.retiringNext.IsZero() { return }          // one load + compare when none
now := p.rotation.read(); if now.Before(set.retiringNext) { return }
p.reloadMu.Lock(); defer p.reloadMu.Unlock()
set = p.secrets.Load(); if set.retiringNext.IsZero() || now.Before(set.retiringNext) { return }
p.swapSecretConfigLocked(set.toConfig())   // the build at now drops expired entries; closeStaleConns
                                           // closes their streams; the change is logged (§6.3)
```

- The expiry swap rebuilds from the **current** set, so API overrides survive it. The lock
  order is `reloadMu` → `liveMu` → `tableMu`, as for every swap.
- The swap cannot be refused: retiring entries never count toward `SecretsCanFront`, and the
  primaries are unchanged.
- One swap happens per distinct expiry instant. At 5,000 secrets the rebuild costs about
  10,000 SHA-256 blocks of pad precomputation (about 3.4 ms on the bench box, from piece A's
  per-block figure). The benchmark measures it (§13).
- **Precision.** New handshakes stop at `until` exactly (§3). Live streams are closed within
  5 s.
- **No extra grace.** The overlap is the grace the operator chose. A second grace would make
  the real deadline something no file states.
- **Rejected:**
  - a timer per entry: more goroutines to stop, and the 5 s sweep already exists;
  - leaving expired entries in the set until the next reload: they would cost scan slots
    indefinitely;
  - closing streams only, without a swap: same objection.

### 4.3 Registration re-checks the key (D16)

`tryRegisterConn` gains a first step, before the ban re-check and before anything the
rollback must undo:

```go
cur := p.secrets.Load()
if cur != ctx.attrSet || !ctx.retiringUntil.IsZero() {        // pointer compare in the common case
    if !cur.accepts(ctx.secretName, ctx.matchedSecretKey, p.rotation.read()) {
        return refuse(DenyKeyRevoked)
    }
}
```

`accepts` does a binary search for the name, compares the primary key, then checks the name's
`retiringOf` entries (key equal and `now < until`).

A swap stores its set **before** it takes `liveMu` to walk `liveConns`. A stream is therefore
either registered before the walk (and judged by `closeStaleConns`), or registers after it
(and reads the new set here). This closes the new race (a retiring key that expires, or is
removed, between `attribute` and registration). It **also closes the existing race** for a
plain re-key described under "Where things stand", which is a behaviour change. It can only
refuse a connection whose key the set no longer accepts. It is tested with
`registerStepHook`-style seams, never by hammering.

`ctx.attrSet` is cleared once registration passes, so a long-lived stream does not pin a whole
old set (candidates and pad states) for hours. `matchedSecretKey` still points into the key
array of the set it was attributed from, as it does today.

`DenyKeyRevoked` (`String() == "key_revoked"`) is a new internal `DenyReason`. Its
`countAdmissionRefusal` case only logs: no counter and no event, as for bans. On the FakeTLS
door it is a close after the server's flight, like an ip-limit refusal. On the obfuscated door
it takes `denyObfuscated`.

**Alternative rejected:** re-checking only streams on a retiring key. That leaves the existing
re-key race open. The cost of covering everyone is one atomic load and one pointer compare per
admission.

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
| `PUT /secrets` (`ReplaceSecrets`) | the current entries of every name the PUT keeps, merged **under `reloadMu`** (`cfg.Retiring == nil` means "keep"; a non-nil slice, which only a library caller can send, replaces them); entries of names the PUT drops go with them |
| `POST /secrets` (`PutSecret`) | the name's entries are kept; if the new primary equals one of them, that entry is dropped (the primary wins, rule 6 at engine level); a new primary never becomes a retiring entry |
| `DELETE /secrets/{name}` | the name's entries go (`forget`) |
| `PUT`/`DELETE /adtag` | kept (via `toConfig`) |

**Why PUT keeps them, when POST clears limits that are not sent.** The API cannot express a
retiring entry (D18). An absent field can therefore only mean "this request is not about
rotation", not "clear it". If PUT cleared them, every rotation-unaware client (the panel
today) would end every overlap as a side effect. The next restart would then grant them again
from the file, a kill-then-revive the operator never asked for.

The merge happens under `reloadMu`, against the set as it is at that moment. A PUT therefore
cannot re-add an entry that a reload or the expiry sweep removed after the handler read the
body. A panel re-key stays immediate: the PUT's old primary is gone, and it never becomes a
retiring entry.

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

### 6.2 Logs

All lines carry `secret_name` and times; none carries a key.

| When | Level | Message | Fields |
|---|---|---|---|
| start and every swap, per entry that is new in this set | Info | `secret accepts a previous key until its overlap ends` | `secret_name`, `until` |
| an entry leaves the set because it expired | Info | `previous key of the secret is no longer accepted: overlap ended` | `secret_name`, `until`, `closed` |
| an entry leaves the set otherwise (file edit, removal) | Info | `previous key of the secret is no longer accepted` | `secret_name`, `reason`, `closed` |
| a config problem | Warning | (§1.3 line) | |
| an engine drop | Warning | `a retiring key was ignored` | `secret_name`, `reason` (`dangling`, `key_of_other_secret`, `over_cap`) |
| the wall clock is behind | Warning | §2.3 | `behind_by` |
| a refused registration | Info | `connection denied by per-user limit` | `deny_reason=key_revoked` |

Info is what `debug = true` shows, as for bans and kicks. The `/stats` fields are the
always-on view.

### 6.3 Change detection

`swapSecretConfigLocked` diffs `oldSet.retiring` with `newSet.retiring`, matching entries by
(name, key) and never logging the key, to choose the lines above. A swap that changes nothing
about rotation logs nothing about it.

## 7. The operator surface: `mtg-proxy rotate-secret` (D22–D26, D32)

### 7.1 Command and flags

The name parallels `generate-secret`, and the config path is the first positional argument, as
in `run`, `access` and `doctor`.

```
mtg-proxy rotate-secret <config-path> <name> --overlap <duration> [--host <hostname>]
                        [--prune] [--dry-run] [--reload] [--in-place] [--force]
mtg-proxy rotate-secret <config-path> <name> --end-overlap [--prune] [--dry-run] [--reload] [--in-place] [--force]
mtg-proxy rotate-secret <config-path> --prune [--dry-run] [--reload] [--in-place] [--force]
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
- **`--in-place`**: §7.4.
- **`--force`**: proceeds past the two refusals that are guesses (§7.6 and the binary
  pre-check in §7.5), never past a validation failure.
- A new block for a name that already has 4 unexpired entries is refused (`--prune` runs
  first). The tool never drops an existing grant to make room.

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
with `github.com/pelletier/go-toml/v2/unstable` (`Parser` with `KeepComments`; `Node.Raw` gives
each key's and string's byte range; the repo pins v2.4.3) and splices the original bytes.

1. **Read and check.** Read the file. `config.Parse` the raw bytes; it must parse, and `Validate`
   must pass. Compute `RetiringSecrets(now)` with one fixed `now` for the whole run. Existing
   problems are warned about but do not block an urgent rotation; new ones do (step 5).
2. **The new primary.** Find the string node of the name's value. The full key path is the
   current table's path plus the key, so `[secrets] shared = …`, `secrets.shared = …` and
   `secrets = { shared = … }` all resolve. For `"default"`, the node is the top-level `secret`.
   Replace that node's `Raw` range with the new value in the original quote style (basic or
   literal). Multi-line strings are refused as an unsupported form.
3. **A new block.**
   - Inserted immediately before the `[secrets]` header line, and before the run of comment
     lines directly above that header, so a heading comment stays attached to it.
   - With no `[secrets]` header (the single-secret form, or dotted or inline secrets), it is
     appended at the end of the file, after a newline if the file lacks a final one.
   - The block carries its own `# added by mtg-proxy rotate-secret at <time>` comment **inside**
     the block, after the header.
   - Line endings follow the file (CRLF if its first line ends in CRLF). A UTF-8 BOM is kept.
4. **Removing a block** (`--prune`, `--end-overlap`). Removed: from the start of the block's
   header line up to the start of the next header line, or to the end of the file. That end
   point is first walked back over the comment and blank lines directly above the next header,
   so a comment that heads the next table survives. A comment a person wrote inside a removed
   block goes with it (documented).
5. **Verify by re-parse (the safety net).** `config.Parse` the new bytes. Not
   `utils.ParseConfig`: its environment overlay and validation would hide or fail the diff. The
   result must equal the old parse in **every** field (`reflect.DeepEqual` on `Config`,
   `UnknownKeys` included) except two:
   - the name's primary, which must equal the generated secret;
   - `RetiringSecrets`, which must equal the old list minus the removed entries plus the new
     one, compared as raw (name, secret, until) triples.

   `Validate` must still pass, and `RetiringSecrets(now)` must report no problem the old file
   did not have. Any difference means nothing is written: `internal error: the edit changed
   more than it meant to; nothing was written`. This catches every layout the splice
   mishandles, including a user appended after the block that would otherwise fall inside it
   (`UnknownKeys` would differ).

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
   holding the pid and the start time, and remove it on exit. An existing lock is a refusal
   that names the file and its age. The tool never breaks a lock itself.
4. **Optimistic check** against other writers (an editor, the panel): just before the rename,
   re-read the target. If its SHA-256 differs from the bytes parsed in step 1 of §7.3, abort:
   `the file changed while rotating; nothing was written`. A small window is left between that
   read and the rename; it is documented.
5. **Write.** The temp file is `<target>.rotate-<8 random hex>.tmp`, created `0600`. Write, then
   `Sync`, then `Chmod` to the original permission bits. On Unix, when the temp's owner
   differs, `Chown` to the original uid and gid; a failure is a refusal (`run as the file's
   owner or root`), because a root-owned `0640` file would be unreadable to a proxy running as
   `mtg-proxy`. Close, `Rename` over the target, then fsync the directory on Unix (not
   possible on Windows; skipped).
6. **`--in-place`, for a single-file bind mount** (the documented Docker form,
   `-v …/config.toml:/config/config.toml:ro`). A rename on the host gives the path a new inode,
   while the container keeps the old one until it is recreated, so a `POST /reload` re-reads the
   OLD file. The read-back in §7.5 catches that. `--in-place` instead copies the current bytes
   to `<target>.rotate-backup` (fsynced), then writes through the existing inode (`O_TRUNC`,
   write, `Sync`). It is not atomic: a crash mid-write leaves the backup, and the documentation
   says so. A rename that fails with `EBUSY` (the target is a mount point) is reported as
   `cannot replace <path>: it is a mount point (a single-file bind mount?); run rotate-secret
   on the host with --in-place`.

### 7.5 `--reload` (D26)

- **Address.** It reads `api-bind-to` and `api-token` from the file. A host of `0.0.0.0` or
  `::` is reached at `127.0.0.1` or `::1`. A missing `api-bind-to` is a refusal before anything
  is written.
- **Before writing:** `GET /stats`. An unreachable API is a refusal (the operator asked for a
  reload; writing without one would half-apply). If `features` lacks `secret-rotation` (an
  older running binary, which would ignore the block and kill the old key at the reload), it
  refuses unless `--force`.
- **After writing:** `POST /reload`, then `GET /secrets/{name}`. The `secret` field must be the
  new value. With an overlap, `retiring_until` must equal the written `until`.
- **A mismatch:** exit non-zero with `the file is rotated but the proxy does not serve it:
  <what differs>; possible causes: a SECRET environment variable overriding [secrets], a
  single-file bind mount that still shows the old file (use --in-place), a clock far ahead`.
- **A failed reload:** exit non-zero with the same "the file is rotated" wording. The file is
  never rolled back: it is the truth, and a rollback would revive the leaked key at the next
  restart.
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
- The scan stays constant-time over both lists.
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
| Wall clock jumps forward | Overlaps end early, then the high-water mark keeps them ended. Fails safe. A Warning is logged when the wall clock is behind the mark (§2.3). |
| Wall clock steps back, same process | No effect on expiry decisions (high-water). |
| Wall clock steps back, then a restart | An entry may be accepted again for up to the size of the step. Mitigation: `--prune` after each overlap; NTP. Risks. |
| A reload arrives after `until` | The entry is inert at build; its streams are closed by `closeStaleConns` in that swap. |
| The file holds an expired entry | Inert forever. `doctor` counts it, `--prune` removes it. |
| Crash between the write and the reload | The running proxy serves the old primary until a reload or restart, and then the file's state. Nothing is revived. |
| Crash during the write | The rename never happened, so the old file is intact. A stale `.tmp` and the lock file remain; the next run refuses on the lock and names it. `--in-place`: the backup file remains. |
| Two proxies share one file | Each applies the same absolute `until` on its own reload. `--reload` reloads one, and the documentation says to reload each. |
| Time zones | `until` is an instant; the CLI writes UTC. |
| A very long overlap | Over 720 h is a problem (dropped, `--check` refuses), and the CLI refuses it. An overlap is a migration window, not a second permanent key. |
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
permissions, which `rotate-secret` preserves. It is in no other file.

## 12. Proof: tests (written first, each sabotage-checked)

Test seams:
- `rotationClock.now` is injected;
- the maintenance sweep interval (`startMaintenanceEvery`);
- `registerStepHook`, plus a new `afterAttributeHook` between `attribute` and `admit`, which is
  a no-op in production;
- address-controlled connections (`dialProxyFrom`) for hinted cases.

No wall-clock sleeps decide an outcome.

**Engine (E)**
- E1. `buildSecretSetAt` covers rules 2, 3, 5, 6, 7 and 8 at engine level, with the order and
  determinism of `retiring`, `cands` order (primaries first), `retiringCands`, `retiringNext`,
  and hosts in `hostnames` and `coverHosts`, but not `frontHost`.
- E2. With no retiring entries every new field is nil or zero, and the set is `DeepEqual` to
  `buildSecretSet`'s.
- E3. `toConfig` → `buildSecretSetAt` round-trips retiring entries.
- E4. `forget` drops them.
- E5. `rotationClock`: backwards steps never lower `read()`, and the Warning is logged once per
  episode.

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
- D5. dd and plain old keys on an obfuscated listener attribute to the right name and key
  (index mapping), and are refused after `until`.
- D6. A mode change across a rotation (old dd, new ee) serves both doors during the overlap.
- D7. A host change across a rotation: the old host passes the SNI gate during the overlap and
  is fronted after the expiry swap.

**Lifecycle (L)**
- L1. A rotation swap keeps every live old-key stream and every new-key stream open.
- L2. The expiry sweep closes exactly the old-key streams within one (test-shortened) sweep.
- L3. An `--end-overlap` reload closes them at once.
- L4. A re-key with no overlap closes every stream of the name (today's behaviour, unchanged).
- L5. `afterAttributeHook` swaps in a set without the key, and registration refuses with
  `key_revoked`, both for a retiring key and **for a plain re-key** (the existing race,
  fixed).
- L6. A swap that does not change the name's accepted keys takes the fast path (counted by a
  test-only counter).
- L7. Ban and kick apply to both keys.
- L8. Quota is shared by both keys.

**API (A)**
- A1. `PUT /secrets` keeps the entries of names it keeps and drops those of names it removes.
- A2. `POST /secrets` re-keying onto a retiring key drops that entry, and its streams stay open
  under the now-primary key.
- A3. `DELETE` drops them.
- A4. `POST` for another name keeps all entries (`toConfig` carries them).
- A5. A PUT racing the expiry sweep cannot re-add an expired entry (lock seam).
- A6. `POST /reload` replaces them with the file's.
- A7. `/stats` and `GET /secrets/{name}` carry the four fields only when relevant, and the
  shapes stay byte-identical for a config without rotation
  (`TestStatsOmitemptyShapeUnchanged` untouched and green).
- A8. `retiring_connections` equals N right after a rotation with N live old-link streams.
- A9. The feature list is sorted and includes `secret-rotation`.

**Config (C)**
- C1. Every row of §1.3, as a problem or inert, with value-free messages.
- C2. `until` as a quoted string, an offset date-time, a local date-time (problem), a date
  (problem) and an integer (problem, not a parse failure).
- C3. A wrong-typed `secret` or `name` is a problem, not a parse failure.
- C4. `Validate()` never fails because of retiring entries.
- C5. `run --check` refuses problems and accepts inert entries.
- C6. The env `SECRET` clears them.
- C7. `Config.String()` redacts them and is byte-identical without the table.
- C8. **Leak sweep:** a scripted rotation (CLI, reload, API reads, a refused reload, problem
  lines, `/reload` 500 bodies, debug logs) never shows the retiring value in any spelling.
- C9. **Monotone acceptance:** a seeded generator of files and times asserts that accepted at
  *t* implies accepted at *t′ > t*.
- C10. The panel-emitted config yields no unknown keys and no problems.
- C11. An unknown field inside the block is an unknown key.

**CLI (R)**
- R1. Rotation on a corpus of layouts:
  - the example config;
  - the panel's emitted layout (with `--force`);
  - dotted and inline `[secrets]`;
  - the single top-level `secret`;
  - CRLF line endings and a BOM;
  - no final newline;
  - comments above `[secrets]`;
  - existing blocks.

  Each case checks the output bytes against a golden file and passes the re-parse diff.
- R2. An injected bad splice (a test seam) is caught by the verification, and the file is
  byte-identical afterwards.
- R3. `--prune` and `--end-overlap` keep a comment that heads the next table.
- R4. The lock refuses a concurrent run, and a changed file aborts before the rename.
- R5. Permissions are preserved; a non-writable file is refused; a symlink target is written
  in place of the link.
- R6. `--in-place` keeps the inode and leaves a backup.
- R7. stdout is exactly one line, the new value; stderr never contains the old value.
- R8. `--dry-run` writes nothing and generates no key.
- R9. `--overlap` is required; the 720 h bound holds; the 5th entry is refused; `--host` with dd
  is refused.
- R10. `--reload` against a test proxy: the feature pre-check (refused without
  `secret-rotation` unless `--force`), the reload, the read-back mismatch message, and the
  unreachable-API refusal before writing.
- R11. The panel-path heuristic refuses, and `--force` passes it.

**WEB relay (W)**
- W1. A retiring capability (expired or not) gets the local 404 and never reaches a recording
  cover upstream.
- W2. It never serves the bridge.
- W3. A retiring-only file change does not reload the profiles, but does update the retired
  list.
- W4. A collision with a live capability keeps the live one.

**Sabotage list.** Each test above fails when its behaviour is removed:
- put retiring candidates before primaries;
- forget to try a hinted name's retiring keys;
- drop the admission expiry check;
- drop the sweep;
- make `closeStaleConns` key-blind (close all on a primary change) or name-only on removal;
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
- write non-atomically without `--in-place`;
- print the old value;
- let the relay `Lookup` a retired capability;
- make a problem refuse the load under `run`;
- check expired entries for dangling names;
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

  The two deliberate changes for everyone: the registration re-check (D16), which only refuses
  a key the set no longer accepts, and the `secret-rotation` feature string.
- **Downgrade:** an older binary ignores the table and kills every old key at once, which is
  safe. `run --check` on the older binary refuses the file, for whoever stages binaries.
- **Version gate for tooling:** the `secret-rotation` feature.

## 15. Task decomposition (for the plan author)

| # | Task | Depends on | Review focus |
|---|---|---|---|
| 1 | **Set building**: `RetiringSecret`, constants, `SecretConfig.Retiring`, `ProxyOpts.RetiringSecrets`, `buildSecretSetAt` (rules, order, candidates, hosts, cover hosts, `retiringNext`), `toConfig`/`forget`, NewProxy wiring | — | nil-when-none; determinism; primary always wins; `frontHost` and `SecretsCanFront` untouched |
| 2 | **Rotation clock**: `rotationClock`, injection, behind-warning | — | monotonicity; no wall-clock decisions elsewhere |
| 3 | **FakeTLS door**: split scan loop, lazy expiry, hinted positions with retiring and the cap of 32, `matchAt`, `attribute`/`completeFakeTLS` carrying the key, `ctx.attrSet`/`retiringUntil` | 1, 2 | byte-identical loop 1; budget arithmetic; golden server flight |
| 4 | **Obfuscated door**: key list and index mapping, expiry | 1, 2 | allocation unchanged when none; off-by-one |
| 5 | **Lifecycle**: per-stream `closeStaleConns` with fast path, registration re-check + `DenyKeyRevoked`, `expireRetiring` in the sweep, change logging | 3, 4 | lock order; the race seams; the plain re-key race fix |
| 6 | **API mutations**: `ReplaceSecrets` keep-merge under `reloadMu`, `PutSecret`/`DeleteSecret`/adtag paths | 1, 5 | no revival through a PUT; panel re-key immediate |
| 7 | **Read-backs**: four fields in `/stats` and `SecretInfo`, read-time `retiring_connections`, `retiring_last_seen`, feature string | 5 | shapes unchanged without rotation; nothing under `users` |
| 8 | **Config**: tomlConfig `any` fields + normalisation, `Config.RetiringSecrets(now)`, problems, `--check`, doctor, env clear, `String()` redaction, wiring in `run` and the reloader | 1 | value-free messages; monotone acceptance; `Validate` untouched |
| 9 | **CLI `rotate-secret`**: unstable-parser locator, splice rules, re-parse verification, atomic write, lock, hash check, `--in-place`, panel heuristic, dry-run, prune/end-overlap, output | 8 | the corpus; never prints the old value; verification cannot be bypassed |
| 10 | **CLI `--reload`**: feature pre-check, reload, read-back | 7, 9 | refusal before writing; never rolls the file back |
| 11 | **WEB relay**: retired capabilities in tier two, registry and reload compare | 8 | constant-time scan; never `Lookup` |
| 12 | **Docs and benchmarks**: example config, wiki (Configuration, Multi-User-and-API, Security, Monitoring, WEB-Proxy-Setup, FAQ, Home table), README; bench rows and the box A/B | all | every claim matches the code; the bar met |

Tasks 1 and 2 can run in parallel; then 3 and 4 in parallel; 8 can start after 1.

## Docs to update

- **`example.config.toml`**: a commented `[[retiring-secret]]` block before `[secrets]`, with
  the placement rule and the CLI.
- **Configuration.md**: the table, problems vs inert, `--check`, `--prune`.
- **Multi-User-and-API.md**:
  - "Kick, ban or re-key" gains a "rotate" row and replaces "Rotation … is not part of this
    release" with a section on rotation: the CLI, the state machine, what mutations do to
    retiring keys, the four fields;
  - "What a mutation does to live connections" gains the per-stream rule;
  - "Mutations are in-memory only" gains the D17/D18 reasoning.
- **Security.md**: the overlap as a grant, crowding out ip-limit slots, the guidance for
  `--overlap 0`, oracles and timing, the restart/clock residual risk; and replace the line
  "Rotation with an overlap period, which would let … is not …".
- **Monitoring.md**: the four fields and the log lines.
- **WEB-Proxy-Setup.md**: no overlap on WEB; old capabilities answered locally.
- **FAQ.md**: "how do I retire a leaked link".
- **Home.md** feature table and the README feature list.

## Not in this piece

- An API write path (a `retiring` field on PUT/POST);
- an overlap on the WEB transport;
- SIGHUP for `run`;
- per-key counters;
- new events or Prometheus/statsd metrics (the four `/stats` fields are the whole view);
- a rotation UI or adoption in the panel;
- automatic pruning of the file by the proxy (it never writes the file);
- `doctor` checks beyond the problem list and the expired count;
- tier-two recognition of keys that were re-keyed or removed without a block;
- the pre-existing echo of `[secrets]` values in `Secret.Set`'s error text.

## Risks

- **Clock step back across a restart** can accept an old key again for up to the size of the
  step. Mitigated by `--prune` and by NTP; it cannot be closed without persistent state, which
  the proxy must not write.
- **High-water poisoning.** A forward jump and its correction end every overlap early for the
  rest of the process. It fails safe and is logged; a restart clears it.
- **A public leak during the overlap can crowd out legitimate users** (ip-limit, client-conns,
  quota). The documentation's guidance is short overlaps or `--overlap 0` plus bans.
- **go-toml `unstable`** has no compatibility promise. It is pinned by `go.mod`, and the
  re-parse verification turns any behaviour change into a refusal, never a bad write.
- **The file edit.**
  - TOCTOU between the hash check and the rename.
  - Comments inside a removed block are lost.
  - `--in-place` is not atomic.
  - All three are documented.
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
  that `rename` onto a bind-mount target fails with `EBUSY`. This is from general knowledge of
  Linux bind mounts, not tried here.
- That go-toml v2.4.3's `unstable.Parser` gives exact `Raw` ranges for every string form (basic,
  literal, inside inline tables and dotted keys). Read from its source (`parser.go` sets `Raw`
  on string nodes); not exercised. Task 9's corpus is the proof.
- That go-toml's `DecodeError.Error()` never quotes document text: relevant only to
  pre-existing parse errors.
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
3. `PUT /secrets` keeps retiring entries (`nil` = keep), unlike POST's "absent clears" for
   limits (D17).
4. Retiring candidates come after all primaries (D9). Cost: an old-link client pays a full scan
   after a restart (empty hints) and is the last scanned in a flood.
5. The registration re-check covers every stream and fixes the pre-existing re-key race (D16),
   a deliberate behaviour change.
6. Retiring ee hosts join the SNI gate and cover hosts (D7), enabling host-changing rotations.
7. A high-water rotation clock (D10), with its poisoning trade-off.
8. Caps: 4 per name, 4,096 in all, 720 h; and 32 hinted verifications (D6, D12).
9. `--overlap` is required, with no default; `--reload` is opt-in (D26, D32).
10. The panel-path heuristic with `--force` (D25).
11. WEB: no overlap; retiring capabilities are tier two (D28).
12. The surgical text edit with re-parse verification, rather than a TOML re-marshal (D23).
13. The four read-back scalars; `retiring_connections` is computed at read time (D19, D20).
14. Expiry closes live streams within 5 s, with no extra grace (D11).
15. No SIGHUP for `run` (D27): a SIGHUP ends the process today, and changing that is not
    additive.

## Revision notes

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

  An independent adversarial review follows.
