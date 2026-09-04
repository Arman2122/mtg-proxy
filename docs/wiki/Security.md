# Security

This page describes what mtg-proxy defends against, how each defence works, and
where the edges are. It is written for an operator deciding how to deploy, not
for someone auditing the code — though every mechanism below names the file it
lives in, so you can check.

Sections on this page:

- Threat model
- Replay protection
- Domain fronting
- The obfuscated2 door
- The WEB relay
- IP blocklists and allowlists
- The management API
- What gets written down
- Client addresses
- Verifying what you run

## Threat model

Two adversaries are in scope.

**A network observer who wants to identify or block Telegram traffic.** This is
the one the design is built around. The observer can watch every packet, can
connect to your port and send anything, and can replay what it saw a legitimate
client send. It cannot read TLS it does not hold the key for.

**A hostile client who wants to reach something it should not** — another user's
traffic or counters, the management API without its token, or a destination the
proxy should refuse to relay to.

Explicitly **not** in scope:

- **Denial of service by volume.** Someone with more bandwidth than your server
  wins. The per-IP handshake budget and the concurrency limit bound specific
  cheap attacks, not a flood.
- **An adversary who already has your server.** Everything below assumes the
  host is yours. This matters for the client-address section: a proxy that
  records who connected is a proxy whose seizure records who connected.
- **A misconfigured deployment.** A `[[listener]]` on a public address with
  `public = true` is doing exactly what you told it to. That said, "the unsafe
  thing was too easy to configure" is a legitimate bug report.
- **Telegram itself.** Traffic is relayed to Telegram's data centres or, with an
  ad-tag, through its middle proxies. The proxy does not and cannot hide you
  from the other end.

Report anything in scope privately — see `SECURITY.md` in the repository for the
advisory link and the maintainer's address, not a public issue.

## Replay protection 🔁

An active prober records the first bytes of a real client's connection and sends
them again, sometimes hours later. If the server answers the same way twice, its
software can be classified. mtg-proxy keeps fingerprints of handshakes it has
already seen and refuses the second one.

The cache is a **stable bloom filter** (`antireplay/stable_bloom_filter.go`),
backed by `BoomFilters` and hashed with xxhash. A stable bloom filter resets a
few random cells on every insert, which is how it holds a fixed error rate over
an unbounded stream instead of saturating. `SeenBefore` is a single
`TestAndAdd` under a mutex: asking whether a fingerprint was seen also records
it.

```toml
[defense.anti-replay]
enabled = true
max-size = "1mib"
error-rate = 0.001
```

`max-size` is the memory the filter is allowed (defaults to 1 MiB when the key
is absent, and the size suffixes `kib`/`mib`/`gib` apply); `error-rate` is the
false-positive rate the filter maintains (default `0.001`).

**`enabled` is not on unless you write it.** The header of `example.config.toml`
says every option there shows its default, but the code reads this key as
`Get(false)` in `internal/cli/run_proxy.go`, so a config that omits the whole
`[defense.anti-replay]` table runs with the no-op cache. The shipped example has
`enabled = true` in it. If you built your config by deleting the parts you did
not need, check this one.

The filter is probabilistic. At the default error rate roughly one handshake in
a thousand is reported as a replay when it is not, and that client is sent to
the cover site. It reconnects with a fresh session ID and succeeds. Lowering
`error-rate` costs memory for the same capacity.

### The two check sites

Both live in `mtglib/proxy.go`, and they key on different things because the two
doors present different bytes.

**FakeTLS, in `doFakeTLSHandshake`.** The key is the ClientHello's session ID.
The check runs immediately after `ReadClientHelloMulti` returns a match — a
ClientHello that fails HMAC never reaches it, because a failed hello is already
being handed to the fronting domain. On a hit the proxy logs a warning, emits a
replay-attack event, and fronts the connection to the matched host.

**obfuscated2, in `doObfuscatedEntry`.** The key is `MatchResult.ReplayKey()`:
the client-chosen AES key and IV, `frame[8:56]`, behind a one-byte domain tag.
That 48 bytes is the complete identity of a replayed handshake, because
identical bytes derive identical ciphers. Bytes `frame[0:8]` and `frame[60:64]`
feed nothing, so keying on the whole 64-byte frame would let an on-path attacker
slip past the cache by flipping a byte he controls.

### Why the obfuscated check runs only after a secret matches

This ordering is deliberate and load-bearing. `SeenBefore` is `TestAndAdd` on a
*stable* filter — **every insert evicts cells**. If unauthenticated 64-byte
probes were allowed to write into it, anyone could point a stream of junk frames
at the obfuscated listener and use it as a remote eraser for the FakeTLS session
IDs the public port depends on. So the trial decryption runs first, and only a
frame that actually matched a configured secret is allowed to touch the cache.

The FakeTLS site has the same property for free: the HMAC has already passed by
the time the check happens.

## Domain fronting 🎭

A prober that fails the handshake must not learn that it failed. mtg-proxy's
answer is to stop being a proxy for that connection and become a pipe to a real
website.

`doDomainFrontingForHost` rewinds the connection — the bytes already read are
put back — dials the fronting target, and relays the two sockets together. The
prober's ClientHello reaches an actual HTTPS server, gets an actual certificate,
and gets actual content. There is no signal to measure, because the answer is
not synthesised.

Four things take this exit:

- an unreadable or non-matching ClientHello (wrong secret, wrong SNI, or a
  timestamp outside `tolerate-time-skewness`, default `3s`);
- a replayed session ID;
- a user who is disabled, expired, or over quota (see
  [[Limits-and-Quotas]]) — the outcome is deliberately identical to a wrong
  secret, so a prober cannot tell "you got the secret right but that account is
  off" from "you got the secret wrong";
- a `[[listener]]`-less deployment with nothing else to do with the connection.

The target is the hostname baked into the `ee` secret. When nothing matched at
all, the proxy falls back to the first configured secret's host in name order.
If there is no fronting host to use, the connection is **closed** rather than
dialed: `net.Dial` treats an empty host as the local system, so a blank target
would make every probe recurse into a fresh connection to the proxy's own port.

Adjust the destination when DNS for the fronting host is blocked or loops back
to this server:

```toml
[domain-fronting]
host = "fronting-backend"
port = 443
proxy-protocol = false
```

`host` takes a hostname or a literal IP and is resolved at dial time. The
hostname from the secret is still what goes in SNI, so the cover site sees a
consistent request. The older top-level `domain-fronting-ip` /
`domain-fronting-port` keys and `[domain-fronting] ip` are deprecated; `ip` is
logged and ignored.

Pick a fronting host that is plausible for your server to be talking to and that
actually serves TLS on the chosen port. `mtg-proxy doctor <config-path>` checks
that the hostname resolves and that the SNI matches. See [[Configuration]] and
[[Troubleshooting]].

## The obfuscated2 door

The `bind-to` port speaks FakeTLS and only FakeTLS. There is no configuration
that makes it accept a `dd` or bare secret, and that is on purpose: a port that
answers obfuscated2 in the clear is fingerprintable as an MTProto proxy, and
turning your main port into one should not be a one-token edit. The project
treats "the default accept posture is `ee` only" as an invariant — it is a
line item on the pull-request checklist in
`.github/PULL_REQUEST_TEMPLATE.md`, not just a convention.

The pre-FakeTLS wire forms get their own stanza instead:

```toml
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
on-unknown-secret = "close"
```

`accept` is required and must be a non-empty subset of `["dd", "plain"]`;
`"ee"` is rejected there. See [[Connection-Types]] for what each form means to a
client.

### `public = true` is an acknowledgement

A `[[listener]]` whose `bind-to` is not a loopback address will not start
without `public = true`. The startup error says why:

```
listener 0.0.0.0:2398 accepts [dd plain] on a public address. A non-FakeTLS
listener answers obfuscated2 and is fingerprintable as an MTProto proxy. Set
public = true on this [[listener]] to confirm, or bind it to 127.0.0.1
```

This is not a warning you can miss in a log. It is a refusal, and the flag is
your written acknowledgement that this socket gives away what it is. The
intended shape is loopback, behind a carrier such as Telegram's own
`tproxy-server` or this project's WEB relay.

`public = true` also arms the per-IP failed-handshake budget:

```toml
handshakes-per-ip = 30
```

Default 30 per second per client IP, burst 2x, minimum 1. It is armed *only*
when `public = true`, and that is the whole reason it is tied to the flag:
behind a loopback carrier every connection presents `127.0.0.1`, so a per-IP
bucket would be one shared bucket an attacker empties for every legitimate user
at once — a self-DoS, not a defence.

### How a refusal is disposed of

Every refusal on this listener takes the same exit. The 64-byte frame is read,
**nothing is written back**, and the connection is disposed of according to
`on-unknown-secret`:

- `close` — close immediately. The default, and the right answer on loopback.
- `drain` — read and discard, bounded to 8 KiB and to the handshake deadline
  already running, then close. For a public listener, where a socket that
  neither answers nor hangs up is less distinctive than a prompt reset.

An unknown secret, an unhonoured transport tag, a replayed frame, a throttled
user and a disabled, expired or over-quota one all take that exit, so none is
distinguishable from the others.

This listener **never** domain-fronts. It does not speak TLS, so relaying a
probe to an HTTPS cover site would pipe that site's TLS alert back out of a
plaintext port — a stronger tell than either close or drain. On a loopback
deployment it would also turn 64 local bytes into an outbound dial and a held
relay pair, which is a pure amplifier with no censor present to fool.

### Known side channels, stated plainly

These are documented in `SECURITY.md` rather than hidden, because an operator
putting this listener on a public address deserves to know what it gives away.

**A rate-limited peer is closed, never drained.** A peer that has spent its
`handshakes-per-ip` budget is read from identically, but it is closed even where
the listener says `drain`. The drain is the longest hold the listener offers,
and giving it to a peer whose budget is gone would turn the budget into a
slot-exhaustion lever. On `close` there is nothing to observe; on `drain` this
is a deliberate timing difference.

**A matched-then-denied frame returns faster than a miss.** Trial decryption
stops at the first key that works, so a frame that matches a secret and is then
refused short-circuits the candidate loop, while a frame no secret matches runs
all N candidates. The gap is bounded by N times one SHA-256 compression plus one
AES key expansion — on the order of 0.5 ms at a thousand secrets — and it is
only measurable by someone who already holds a valid secret.

**A successful handshake is followed by a dial; a failed one is not.** This is
inherent to being a proxy and is not fixable at this layer. It is the strongest
single reason to keep these listeners on loopback.

## The WEB relay

The WEB transport serves a page from a real hostname over real HTTPS and carries
MTProto over a WebSocket from inside the client's WebView. Full setup is in
[[WEB-Proxy-Setup]]; this section is the security reasoning.

The relay runs as a **separate process** of the same binary reading the same
config file. The proxy ignores the `[web]` table entirely, so an unusable relay
configuration cannot take the MTProto port down. Check it on its own:

```bash
mtg-proxy web-relay --check /etc/mtg-proxy/config.toml
```

### Three-tier recognition

Every request the relay's origin receives lands in exactly one of three classes,
and the classification happens before any routing decision
(`internal/webrelay/origin.go`, `internal/webrelay/capability.go`):

1. **Authentic and usable** — a canonical bridge capability or a valid token.
   Serve the bridge page, or carry the session.
2. **Authentic but unusable** — the value really is one of this relay's own
   credentials, but something disqualifies it: expired, already spent, a padded
   or standard-alphabet spelling, a set trailing bit, the wrong path, the wrong
   method, a duplicated query field. Answered **locally** with an uncacheable
   404.
3. **Everything else** — the ordinary cover site, unaltered, on every path
   including API-looking ones, which may be genuine routes of whatever site is
   being fronted.

Tier two is the one that exists for a security reason rather than a routing one.
Handing an authentic-but-unusable request to the cover site would write an
operator's **real capability into a third party's access log**. That leak is
unrecoverable, which is why the recognition is deliberately lenient about
spelling: a capability mangled by a proxy that turned `+` into a space is still
recognised, so it still gets the local 404 instead of being forwarded.

The consequence for deployment: **this origin must be the only gateway for its
hostname.** Routing some paths around it re-creates the distinguisher the three
tiers remove — a prober would see one component's 404 and another's, and could
tell them apart by header order and timing.

### The cover site has no default

```toml
[web]
cover-dir = "/srv/site"
# or exactly one of:
# cover-upstream = "http://127.0.0.1:8080"
```

The relay refuses to start with neither or both. Nothing ships as a default,
and that is a decision rather than an omission: a starter page many operators
installed would itself become the signature. The body, the asset set and the
response timing of "the thing relay operators serve" would be a far better
distinguisher than anything the protocol leaks.

Serve something plausible for the hostname you chose. Directory listings are
disabled for `cover-dir` — a directory without an `index.html` is a 404 — because
an index of your files is both an information leak and a fingerprint, Go's
listing markup being recognisable at a glance.

### The stats socket must be loopback

```toml
stats-bind-to = "127.0.0.1:8100"
```

```bash
curl http://127.0.0.1:8100/stats
```

Empty is the default and means no stats server. If it is set to anything that is
not a loopback IP literal, the relay **refuses to start** (`ValidateStatsBind`
in `internal/webrelay/stats_server.go`). A hostname is refused too, because a
name could resolve anywhere and could resolve somewhere else tomorrow.

Refused rather than warned about, for a specific reason: this socket answers,
with no credential at all, how many sessions are live and how many bytes have
moved. That is exactly the traffic analysis this transport exists to deny. An
operator who typed `0.0.0.0` has published it, and a line in a log is not where
they would find out.

It is also deliberately **not** a path on the public `bind-to`. That socket is
published to the internet by the front proxy and holds one invariant: anything
not carrying a credential this relay minted is answered by the cover site, on
every path. A real endpoint there breaks it — a 401, a JSON body, or even a
distinctive response time says this hostname is not the website it claims to be.
Token-gating would not help, because the gate itself is the fingerprint. See
[[Monitoring]].

### The token signing key

```bash
mtg-proxy generate-web-key /etc/mtg-proxy/web.key
```

32 bytes, mode 0600, and the relay will not start without it. It is never
generated at startup, and `generate-web-key` refuses to overwrite an existing
file.

A key invented on a missing file would work perfectly until the first restart,
at which point every token the relay had ever minted becomes unrecognisable —
and unrecognised credentials go to tier three, which means the relay would start
handing its own live users' tokens to the cover site. A key readable by group or
other is refused for the obvious reason: anyone who can read it can mint values
that look authentic to the recognition tier. The permission check is skipped on
Windows, where a mode triple does not express the ACL.

Rotating the key invalidates every live session. So does changing `[web] host`,
which invalidates **every WEB link ever issued** — the hostname is HMAC input to
the capability derivation, exactly as an `ee` secret's fronting domain is.

### Secret forms and client addresses

A WEB-capable client **refuses an `ee` secret** before it opens a socket. WEB
links carry the `dd` spelling of the same sixteen key bytes, which is why
`ValidateWeb` refuses a `[web] backend` that names a `[[listener]]` not
accepting `dd`, and why `mtg-proxy access` prints the `dd` form for these links.
One account, three doors.

How the relay learns the browser's address is a security setting, not a
cosmetic one:

```toml
client-ip = "proxy-protocol"
```

`proxy-protocol` is the default and is **required once chosen**: the listener
runs the PROXY protocol in `REQUIRE` mode, so a connection without a header is
refused rather than attributed to the loopback. `x-forwarded-for` takes the
right-most entry and only from a loopback peer, because a header is meaningful
only from the hop that appends it.

There is no fallback to the socket's own peer address. Behind a front proxy that
is `127.0.0.1` for every user alive, and stamping it into the backend header
would quietly turn off the IP blocklist, stop the per-IP limits counting, and
make every log line name the loopback — while the relay kept working perfectly.
A stream whose client cannot be identified is refused instead.

The same reasoning applies to the `[[listener]]` the relay dials: set
`proxy-protocol = true` on that stanza if you want real client addresses to
reach the proxy. Telegram's own `tproxy-server` sends no header, so leave it
false if that is your carrier.

## IP blocklists and allowlists 🚧

Both are FireHOL-format range sets, checked in the accept loop before the
connection reaches a worker.

```toml
[defense.blocklist]
enabled = true
download-concurrency = 2
urls = ["https://iplists.firehol.org/files/firehol_level1.netset"]
update-each = "24h"
```

```toml
[defense.allowlist]
enabled = false
download-concurrency = 2
urls = []
update-each = "24h"
```

Entries may be `https://`/`http://` URLs or absolute paths to local files. Both
tables read `enabled` as off when the key is absent. A disabled allowlist is
built as an all-IPv4-plus-all-IPv6 range set, so it permits everything; the two
can be combined, and the allowlist is consulted first.

**A rejected connection is closed, not fronted.** The proxy closes the socket
before reading a byte and logs `ip was rejected by allowlist` or `ip was
blacklisted`. The comment in `example.config.toml` that says such clients are
routed to the fronting domain describes an older behaviour and is stale; the
code in `mtglib/proxy.go` closes.

Two limitations worth knowing:

- **Lists load asynchronously.** At startup they are empty and are populated in
  the background. A restart briefly has no blocklist, and an error fetching any
  URL is ignored rather than fatal.
- **`firehol_level1` includes bogons, and therefore RFC1918.** `10.0.0.0/8`,
  `172.16.0.0/12` and `192.168.0.0/16` are in it. If you run the proxy on a LAN
  and connect from the same LAN, that client is dropped with no response. Use a
  narrower list such as `firehol_abusers_1d`, disable the table, or connect via a
  public address. This is the single most common "it just closes the connection"
  report — see [[Troubleshooting]].

Behind a front proxy, what these lists match is whatever the PROXY header
carried, so they are only meaningful if the header is actually being sent.

## The management API 🔑

The API can add, replace and delete secrets, change ad-tags and reset quotas. It
is off unless `api-bind-to` is set.

```toml
api-bind-to = "127.0.0.1:9090"
api-token = "change-me"
```

**Bind it to loopback.** That is the primary control, and when `api-token` is
unset it is the *only* control — the API is unauthenticated and relies entirely
on nobody being able to reach the socket.

`api-token` adds a bearer token required on **every** endpoint:

```bash
curl -H "Authorization: Bearer change-me" http://127.0.0.1:9090/secrets
```

A missing or wrong token gets `401` with `WWW-Authenticate: Bearer`. The
comparison uses `subtle.ConstantTimeCompare` against the full
`"Bearer " + token` string, so the token cannot be recovered a byte at a time by
timing (`withAuth` in `mtglib/proxy_api.go`).

Set a token whenever the socket is reachable from anything but localhost, and
prefer not making it reachable at all — put a panel on the same host, or reach
it over an SSH tunnel or a WireGuard interface, rather than exposing port 9090.
Endpoint reference is in [[Multi-User-and-API]].

## What gets written down

**Debug logging redacts credentials.** `Config.String()`
(`internal/config/config.go`) is what a debug-level start-up log prints, and it
replaces the top-level `secret`, the `api-token`, and **every value in
`[secrets]`** with the literal string `[redacted]`. A fixed string rather than
an empty one, so a reader can tell "not configured" from "not shown".

Secret *names* are kept, because knowing which users are configured is the
entire value of that line and the name is not the credential.

This existed because it did not: switching `debug = true` on used to serialise
the struct verbatim, writing every client's secret and the API token into a log
file where they outlive the process and get picked up by whatever ships logs. A
test (`TestConfigStringRedactsEveryCredential`) fails if a new credential field
is added to `Config` without being added to the redaction list.

The scope is honest but narrow: this covers the config dump, not a blanket
guarantee that no code path anywhere can log a secret. If you add code, the
pull-request checklist asks you to confirm that no secret, token or client
address reaches a log, a persisted file, or an error message.

**The only file the proxy writes is the usage state file.**

```toml
usage-state-file = "/var/lib/mtg/usage.json"
```

It holds per-secret quota byte counters and nothing else. No secret, no
hostname, no address. When unset, quota accounting is in-memory and resets on
restart.

## Client addresses 📍

`track-client-ips` makes `GET /stats` report, per user, the addresses behind
their connections.

```toml
track-client-ips = false
```

```json
"alice": {
  "connections": 2,
  "connected_ips": ["198.51.100.7", "203.0.113.44"],
  "last_ip": "203.0.113.44"
}
```

`connected_ips` is the set of distinct addresses holding a live connection right
now, deduplicated and sorted. It is derived from the connection registry rather
than counted separately, so it cannot drift from `connections` beside it, and an
entry disappears when its connection ends. `last_ip` is the address of the most
recent admitted connection and **outlives that connection**.

### Why it defaults to off

This is a circumvention proxy. The people using it are frequently the reason it
exists, and an operator's answer to "who connected from where" is also the
answer available to whoever ends up with the server — through seizure, a hosting
provider, a compromise, or a subpoena.

`connected_ips` costs no new retention: those addresses are already held for the
life of the connection and vanish with it. `last_ip` is different — it survives
the connection it came from, and a deployment that never asks for it never
accumulates one.

The default is not caution about an unfinished feature. It is the position that
a proxy which does not know something cannot be made to disclose it.

### What it does and does not do

- **Nothing is written to disk in any form.** `usage-state-file` persists quota
  counters only, so no address survives a restart.
- **The fields are absent, not empty, when tracking is off.** `/stats` looks
  exactly as it did before the feature existed, and an absent field is
  indistinguishable from an idle secret.
- **Addresses are recorded only after attribution.** The record happens in
  `admit`, once the secret is known. On the `dd`/`plain` door the user's name
  does not exist until the frame is trial-decrypted, and an address recorded
  earlier would be filed under the empty name for every obfuscated user at once.
- **`features` advertises the capability, not the setting.** The `/stats`
  `features` array contains `client-ips` when the binary understands the option.
  It says nothing about whether this deployment turned it on.
- **Behind a front proxy it reports what the PROXY header carried**, which is the
  client's real address. Without a header being sent, every user is the
  loopback.

### Before you turn it on

Ask what you will do with the value that you cannot do with the counters you
already have. Abuse attribution and "is this account shared with fifty people"
are answered by `connections` and the quota counters without recording anyone's
address. If you need the addresses, prefer reading `connected_ips` live and not
storing it, be clear with your users that it exists, and remember that anything
your panel scrapes and saves has left this process's memory-only guarantee
behind — the proxy's promise not to write addresses to disk does not extend to
software that polls it.

## Verifying what you run 📦

The people who run this proxy are, by design, people whose network is hostile to
them. A binary they cannot verify is a binary someone else can choose.

Every release publishes a checksums file, an SPDX 2.3 SBOM of the module graph
the binaries were built from, and a signed in-toto build provenance attestation
covering every asset — the archives, the SBOM, and the checksums file itself.

Set the version and archive first:

```bash
VERSION=1.3.0
```

```bash
PKG=mtg-proxy-${VERSION}-linux-amd64
```

```bash
BASE=https://github.com/Arman2122/mtg-proxy/releases/download/v${VERSION}
```

**Checksum.** Catches a truncated download, a stale CDN object, a version
mismatch:

```bash
curl -sfLO "${BASE}/${PKG}.tar.gz"
```

```bash
curl -sfLO "${BASE}/mtg-proxy-${VERSION}-checksums.txt"
```

```bash
sha256sum -c --ignore-missing "mtg-proxy-${VERSION}-checksums.txt"
```

It does **not** catch a deliberate substitution. The checksums file is served
from the same origin as the archive, so whoever can replace one can replace the
other. That is what the next check is for.

**Provenance.** Needs the `gh` CLI and no secret for a public repository:

```bash
gh attestation verify "${PKG}.tar.gz" --repo Arman2122/mtg-proxy --signer-workflow Arman2122/mtg-proxy/.github/workflows/go.yml
```

`--signer-workflow` is not optional in spirit. Without it the check accepts an
attestation from *any* workflow in the repository that can mint an OIDC token,
which is a materially weaker claim than "this came out of the release build".

The container image is attested the same way, by its own workflow:

```bash
gh attestation verify oci://ghcr.io/arman2122/mtg-proxy:${VERSION} --repo Arman2122/mtg-proxy --signer-workflow Arman2122/mtg-proxy/.github/workflows/docker-publish.yml
```

Verify a released tag rather than `latest`: attestation started partway through
the project's history, so an older image still sitting under a floating tag may
have none to check.

**SBOM.** `mtg-proxy-<version>-sbom.spdx.json` lets you answer "is this
affected?" when an advisory lands, without re-deriving the dependency set from a
tag.

**If you redistribute mtg-proxy** — in a panel, an installer, a distribution —
verify before you unpack, and **fail the build** when verification fails rather
than warning. An unverified `curl | tar` in a release pipeline turns one
compromised asset into a root-owned binary on every one of your users' servers,
and neither you nor they will see it happen. See [[Installation]].

## A short hardening checklist

- `bind-to` serves FakeTLS only. Leave it that way.
- `[defense.anti-replay] enabled = true` is present in your config, not just in
  the example you copied from.
- Every `[[listener]]` is on loopback, or you have consciously written
  `public = true` and understand the side channels above.
- `api-bind-to` is `127.0.0.1`, and `api-token` is set if anything else can
  reach it.
- `[web] stats-bind-to` is loopback (it will not start otherwise) and the
  hostname serves a cover site you would be comfortable being asked about.
- The WEB token key is mode 0600 and was generated by `generate-web-key`.
- `track-client-ips` is off unless you have a specific reason and have thought
  about what happens to the server.
- You verified the release you are running, and your automation fails closed
  when verification does.
