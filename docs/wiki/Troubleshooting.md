# Troubleshooting

mtg-proxy is two programs. `mtg-proxy run` serves MTProto on `bind-to` and on any
`[[listener]]` you declared. `mtg-proxy web-relay` serves the WEB transport. They read
the same configuration file, they log to their own standard output, and a fault in one
is usually invisible in the other. Decide which one you are debugging before changing
anything.

Each section below is written the same way: what you see, why it happens, what to do,
and a command that tells this cause apart from the others.

- [Reading the logs](#reading-the-logs)
- [The proxy will not start](#the-proxy-will-not-start)
- [Clients cannot connect over FakeTLS](#clients-cannot-connect-over-faketls)
- [mtg-proxy doctor, check by check](#mtg-proxy-doctor-check-by-check)
- [Clock skew](#clock-skew)
- [A dd or plain secret with no listener](#a-dd-or-plain-secret-with-no-listener)
- [The WEB transport sits at "connecting"](#the-web-transport-sits-at-connecting)
- [The relay serves the cover site to real users](#the-relay-serves-the-cover-site-to-real-users)
- [PROXY protocol, in both directions](#proxy-protocol-in-both-directions)
- [Quota, expiry and disable refusals](#quota-expiry-and-disable-refusals)
- [The management API does not answer](#the-management-api-does-not-answer)

## Reading the logs

Both processes write JSON lines to standard output, with `timestamp` and `level` fields.
There is no log file setting and no syslog integration: whatever supervises the process
owns the log.

```bash
journalctl -u mtg-proxy -f --output=cat
```

```bash
docker logs -f mtg
```

**The default level is WARN.** Unless `debug = true` is set, everything below a warning
is discarded before it is written. Most per-connection diagnostics sit below that line,
so the usual reason for "there is nothing in the log" is that the log is not being
written.

```toml
debug = true
```

| Message | Level | Written by default |
|---|---|---|
| `cannot read client hello` (any failed FakeTLS handshake) | info | no |
| `ip was blacklisted` / `ip was rejected by allowlist` | info | no |
| `connection was concurrency limited` | info | no |
| `connection has no usable client address` | info | no |
| `web relay is running` (the relay's own startup line) | info | no |
| `web relay stream ended` (includes a failed backend dial) | debug | no |
| `web relay carrier attached` | debug | no |
| `replay attack has been detected!` | warning | yes |
| `secret is not served by any listener` | warning | yes |
| `cannot start extra listener on <addr>` | warning | yes |
| `SNI-DNS mismatch` | warning | yes |
| `web relay reload: ...` (every refused reload) | warning | yes |

Turn `debug` on, reproduce the fault once, and turn it back off. The debug log also
prints the loaded configuration, but every secret and the API token are replaced with
`[redacted]` first, so that line is safe to keep. It is verbose enough to matter on a
busy proxy, which is the reason to turn it off again.

## The proxy will not start

### The process exits with `cannot init config: ...`

The config is read, environment variables are overlaid, and the whole thing is validated
before a single socket is bound. Three different layers can refuse it, and the prefix
tells you which:

- `cannot parse toml config: ...` — the file is not valid TOML. A syntax error.
- `cannot parse a config: ...` — the TOML is fine but a value is not. For example a
  `[web] bind-to` of `localhost:8099` gives `host is not an IP address: localhost:8099`,
  because every `host:port` option in this file requires a literal IP.
- `invalid config: ...` — the values parse but do not make sense together.

The `invalid config` cases you are most likely to hit:

| Message | Meaning |
|---|---|
| `no secret carries a fronting hostname and domain-fronting.host is unset` | `bind-to` is FakeTLS and has nothing to front a failed handshake to. Keep one `ee` secret, or set `domain-fronting.host` |
| `listener 0.0.0.0:8444 accepts [dd] on a public address` | a non-loopback `[[listener]]` needs `public = true` — see below |
| `accept must be a non-empty subset of ["dd","plain"]` | a `[[listener]]` cannot accept `"ee"` |
| `two listeners bind 127.0.0.1:2398` | one address serves exactly one accept policy |
| `secret-limits refers to unknown secret "alise"` | a typo in a `[secret-limits.<name>]` table |

The `public = true` refusal is not bureaucracy. A socket that answers obfuscated2 in the
clear is fingerprintable as an MTProto proxy by anyone who connects to it, unlike the
FakeTLS port, which looks like a TLS server. Setting `public = true` is your
acknowledgement of that; the flag exists so nobody publishes such a port by editing one
token in an existing line.

Note that `[web]` values must **parse** even for `mtg-proxy run`, which otherwise ignores
that table entirely. A malformed `[web] bind-to` stops both processes; a `[web]` block
that is merely unusable (no `token-key`, no cover site) stops only the relay.

### `permission denied` binding port 443

Ports below 1024 need privilege on Linux and the BSDs. Pick one:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/mtg-proxy
```

Or bind a high port and redirect to it, or let systemd hand the socket over. In Docker
the image runs as root and Docker sets `net.ipv4.ip_unprivileged_port_start=0`, so 443
works out of the box; under Kubernetes and some other runtimes it does not, and you
should bind `0.0.0.0:8443` inside and publish it as 443 outside.

### `address already in use`

```bash
ss -lntp | grep ':443 '
```

Usually a second copy of mtg-proxy that a supervisor restarted, or a web server on the
same port. Note that only the `bind-to` group is fatal here. If an extra `[[listener]]`
cannot bind, the proxy logs `cannot start extra listener on 127.0.0.1:2398` and carries
on serving everything else — losing a WEB backend must never take the public port down
with it. That warning is at WARN level, so you will see it, but nothing else will tell
you: the relay beside it will then fail every stream.

### The config parses, but half your settings did nothing

This is the one that costs the most time, and it is not a bug in mtg-proxy — it is how
TOML works. `[secrets]`, `[secret-limits]`, `[[listener]]` and `[web]` are all table
headers, and **every top-level key written after one belongs to that table.**

```toml
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd"]

api-bind-to = "127.0.0.1:9090"
concurrency = 8192
```

That file starts cleanly and reports no error at all. Both of the last two lines were
parsed as keys of the listener, not of the proxy: the management API never starts, and
concurrency silently falls back to its default of 4096. The proxy will not tell you,
because unknown keys inside a table are ignored rather than rejected — that is
deliberate, since it is what lets a config carrying `[[listener]]` still run on an older
binary.

**Fix: write every global key first, then `[[listener]]` blocks, then `[web]`, and put
`[secrets]` last.** [[Configuration]] shows the whole file in that order.

The same rule caught the other way round does produce an error, which is why it is the
less dangerous half. A `bind-to` line written under `[secrets]` becomes a secret named
`bind-to`, and you get `cannot parse a config: incorrect secret format: illegal base64
data at input byte 1` — an error about secrets when you were editing a bind address.

The corollary: **a mistyped key name is never an error.** `tolerate-time-skewnes` loads
fine and does nothing. If a setting appears to have no effect, check its spelling against
[example.config.toml](https://github.com/Arman2122/mtg-proxy/blob/main/example.config.toml)
before looking anywhere else.

## Clients cannot connect over FakeTLS

The characteristic symptom is silence. When a FakeTLS handshake fails for any reason, the
connection is handed to the fronting domain instead of being closed, so a client sees a
TLS session that is not a proxy and gives up on its own schedule. That behaviour is the
point — it is what stops a prober distinguishing your port from a web server — but it
means a wrong secret, a skewed clock and a blocked IP all look identical from both ends.

First, confirm the port answers at all. Because an unrecognised connection is fronted, an
ordinary HTTPS request to the proxy port comes back looking like the real fronting site:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' --resolve storage.googleapis.com:443:203.0.113.9 https://storage.googleapis.com/
```

Replace the hostname with the one inside your `ee` secret, the address with your server,
and the port in `--resolve` with your `bind-to` port if it is not 443. A normal status
code means the port is reachable and fronting correctly, which rules out the firewall and
the listener in one go. A hang or a connection refusal means the problem is the network
path, not the secret.

Then turn on `debug` and reconnect once. `cannot read client hello` in the log confirms
the handshake was reached and rejected; nothing at all means the connection never
arrived. Work through these in order:

| Cause | How to tell | Fix |
|---|---|---|
| Wrong secret in the client | `mtg-proxy access <config>` and compare | re-issue the link |
| Clock skew on the server | see [Clock skew](#clock-skew) | fix NTP |
| The client's IP is in the blocklist | `ip was blacklisted` with `debug = true` | see below |
| An allowlist is on and does not include the client | `ip was rejected by allowlist` | add the range, or disable it |
| Concurrency ceiling | `connection was concurrency limited` | raise `concurrency` |
| Quota, expiry or disable | [see below](#quota-expiry-and-disable-refusals) | check `GET /secrets` |
| Anti-replay | `replay attack has been detected!` at WARN | usually a real duplicate; investigate |

The blocklist trap is worth spelling out because it catches home installations. The
default list, `firehol_level1.netset`, includes bogon networks, and therefore
10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16. Connect from a client on the same LAN as
the proxy and it is rejected. Either turn `[defense.blocklist]` off, or use a narrower
list, or reach the proxy through its public address.

## mtg-proxy doctor, check by check

```bash
mtg-proxy doctor /etc/mtg-proxy/config.toml
```

It prints a line per check with a pass, warn or fail marker, and exits with status 1 if
anything failed. It reads and validates the config on the way in, so it doubles as the
fastest syntax check for the proxy half of the file. It does **not** look at `[web]` —
that is `mtg-proxy web-relay --check`, and the two are complementary rather than
overlapping.

What each check actually does:

**Deprecated options.** Names the replacement for `domain-fronting-ip`,
`[domain-fronting] ip`, `domain-fronting-port`, `domain-fronting-proxy-protocol` and
`[network] doh-ip`. Read the results carefully, because the five are not equivalent:

- The two **`ip`** options are warned about at startup and then **ignored**. If domain
  fronting is going somewhere you did not intend, or nowhere, this is the first thing to
  check — set `[domain-fronting] host` instead.
- `domain-fronting-port`, `domain-fronting-proxy-protocol` and `doh-ip` are **still
  honoured**, as fallbacks behind their replacements in `[domain-fronting]` and
  `[network] dns`. They work today and will be removed in a later release.

**Time skewness.** Queries `0.pool.ntp.org` and compares the offset against your
`tolerate-time-skewness`. Under 30% of the tolerance passes, under 70% warns, above that
fails. If the NTP query itself cannot be made, the check fails — outbound UDP 123 has to
work for this one, and a firewalled server will fail a check about a clock that is fine.

**Native network connectivity.** Opens a TCP connection to each Telegram core data centre
and completes an RPC probe, reporting the round-trip. A failure here is egress: routing,
a firewall, or an IP family your `prefer-ip` setting excludes.

```bash
mtg-proxy doctor --skip-native-check /etc/mtg-proxy/config.toml
```

Use that when the proxy reaches Telegram through the SOCKS5 entries in
`[network] proxies` and direct egress is not expected to work. Each configured proxy is
then checked the same way, on its own.

**Fronting domain connectivity.** Opens a TCP connection to the fronting host and port —
`[domain-fronting] host` if you set one, otherwise the hostname from a secret. If this
fails, every rejected handshake has nowhere to go.

**SNI-DNS match.** Resolves the secret's hostname and compares the answers against this
server's public addresses. It is expected to fail on an ordinary deployment and that is
fine: FakeTLS fronts a hostname you do not own. It matters only when you *do* point that
name at this server, which is the SNI-router arrangement.

Because that check fails by design on a normal proxy, `doctor` exits non-zero on a
perfectly healthy deployment. Read its output; do not wire its exit status into a health
check or a deploy gate.

Two limitations to know about. The fronting and SNI checks use one secret's hostname
picked out of the map, so with several secrets that use different hostnames the run may
check a different one each time. And the SNI check needs to know your public address: set
`public-ipv4` / `public-ipv6` if automatic detection is unavailable, or the check reports
that it cannot detect one rather than telling you anything about DNS.

The proxy makes a similar SNI check at startup and logs `SNI-DNS mismatch` as a warning,
but only for the single top-level `secret` key. A config using `[secrets]` gets no
startup warning at all, which is another reason to run `doctor` deliberately.

## Clock skew

A FakeTLS ClientHello carries an encrypted timestamp. The proxy decrypts it and, if the
difference from its own clock exceeds `tolerate-time-skewness`, treats the secret as
unmatched — so the connection is fronted, exactly like a wrong secret. The default
tolerance is **3 seconds**. (`example.config.toml` shows `5s`; that file demonstrates
options with sample values, and this is one where the sample is not the default.)

Typical symptoms: nobody can connect after a host migration or a VM restore, or
connections work and then stop after the machine has been up for weeks with no time
synchronisation.

```bash
timedatectl status
```

```bash
chronyc tracking
```

Fix the clock. Raising `tolerate-time-skewness` is the wrong fix in almost every case:
the window is what makes a captured ClientHello useless to replay later, and widening it
widens exactly that. If you must raise it as a stopgap, treat it as a stopgap.

## A dd or plain secret with no listener

`bind-to` is permanently FakeTLS-only and always will be — it is reported as
`"accept": ["ee"]` in `/stats`, and there is deliberately no way to spell "dd on the
public port" by editing an existing key. A `dd` or plain secret is therefore only
reachable through a `[[listener]]` that honours that form.

A secret with no door is stored, valid, and unusable. It is a warning rather than an
error, because one odd client must never be able to take a whole inbound offline — and
because this is the recovery path when an `ee` prefix typo turns a secret into a plain
one. At startup:

```
secret is not served by any listener; no configured listener honours this form
```

And on the API, where it is easier to find:

```bash
curl -sS http://127.0.0.1:9090/secrets | jq '.secrets[] | select(.unserved) | {name, mode}'
```

The coverage rule is asymmetric and catches people. `plain` covers `dd`, but a `dd`-only
listener does **not** cover a plain secret: a bare 16-byte secret places no constraint on
the client's transport, so a plain client is free to choose a transport a `dd` listener
will not honour. If a plain secret shows `unserved` beside a `dd` listener, that is why.

```toml
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
```

Nothing has to be re-issued to fix this. A secret is sixteen key bytes and the same key
is valid in all three wire forms; the prefix only tells the client how to connect. One
user keeps one name, one quota bucket and one set of counters through every door. See
[[Connection-Types]] for which form a given client will take.

One more thing that looks wrong and is not. `mtg-proxy access` prints no links for a
loopback listener, and says so:

```json
{
  "bind_to": "127.0.0.1:2398",
  "accept": ["dd"],
  "public": false,
  "unreachable": "bound to loopback, so it is reachable only from this host (a WEB relay backend is meant to look like this)"
}
```

That is the expected shape of a WEB relay backend, not a misconfiguration.

## The WEB transport sits at "connecting"

The client shows nothing useful, so work down the chain from the outside in. Every step
has a command.

**1. Is the configuration usable at all?**

```bash
mtg-proxy web-relay --check /etc/mtg-proxy/config.toml
```

This validates and exits without binding anything, and it prints the host, listen
address, backend, profile count and client-IP source it would use. It catches the whole
class of "the relay is not running and the unit keeps restarting":

| Message | Meaning |
|---|---|
| `[web] is not enabled in this configuration` | `enabled = true` is missing |
| `[web] host is required: it is the name a client derives its capability over` | set `host` |
| `[web] host "localhost" must be a fully qualified name with a public certificate` | a name with no dot cannot carry a browser-trusted certificate |
| `[web] host "203.0.113.9" is an IP address; a WEB client refuses one` | the client's field takes a hostname, and a certificate has to match it |
| `[web] token-key is required; create one with 'mtg-proxy generate-web-key <path>'` | run that command |
| `WEB relay token key file is missing` | the path is wrong, or the file was never created |
| `WEB relay token key file is readable by group or other` | `chmod 0600` (not checked on Windows, which has no mode bits) |
| `[web] needs exactly one of cover-dir or cover-upstream` | set one, and only one |
| `cannot serve the cover site from "/srv/site"` | the directory does not exist |
| `[web] backend 127.0.0.1:9999 names no [[listener]]` | the address must match a `[[listener]]` exactly, by value |
| `[web] backend ... does not accept dd secrets, which is the only form a WEB client can hold` | add `"dd"` to that listener's `accept` |
| `the WEB relay stats address must be a loopback address` | loopback only, always — see [[Monitoring]] |

Two host mistakes are caught earlier still, at parse time, so they stop `mtg-proxy run`
as well: `host = "web.example.com:443"` gives `host must not contain a port`, and
`host = "https://web.example.com"` gives `incorrect host`. It is a bare name, nothing
else.

The cover site is not optional and no default ships, which is why the relay refuses to
start without one. The hostname has to serve a plausible website to everyone who is not a
Telegram client, and a starter page that many operators installed unchanged would be a
better signature than anything the protocol leaks. Point `cover-dir` at a real site, or
`cover-upstream` at a real application.

**2. Is the certificate real?**

```bash
curl -sSI https://web.example.com/
```

The client validates the certificate inside its own WebView and offers no way past an
error. A self-signed or expired certificate fails silently from the user's side. If curl
complains about the certificate, so will the client.

**3. Is the hostname exactly the one in the link?**

The capability a client presents is derived from the hostname. Changing `host`
invalidates every WEB link ever issued, in the same way changing an `ee` secret's
fronting domain does. A client using a link minted for a different name is not
recognised, so it gets the cover site — a working website, which is why the client sits
there indefinitely instead of reporting an error.

```bash
mtg-proxy access /etc/mtg-proxy/config.toml
```

Compare the `web.host` and `web.secret` in that output against what is typed into the
client, character for character.

**4. Is the secret in the right form?**

A WEB-capable client refuses an `ee` secret before it opens a socket. WEB uses the `dd`
spelling of the same sixteen key bytes, which is what the `web` object of
`mtg-proxy access` prints. Handing a user their existing `ee` link for the WEB field is
the single most common cause of this symptom, and nothing needs re-issuing to fix it —
the two strings are the same key.

**5. Which hop is failing?** Turn on the relay's own counters and read them:

```toml
[web]
stats-bind-to = "127.0.0.1:8100"
```

It must be a loopback address, and the relay refuses to start on anything else. That
socket answers, with no credential at all, how many sessions are live and how many bytes
have moved — which is precisely the traffic analysis this transport exists to deny. It is
also deliberately a second socket rather than a path on `bind-to`, because anything on
the public origin that is not the cover site is a fingerprint however it is gated.

```bash
curl -sS http://127.0.0.1:8100/stats
```

```json
{
  "profiles": ["alice", "bob"],
  "sessions": { "active": 0, "created": 41, "attached": 0, "max": 1024 },
  "streams": { "active": 0, "opened": 0 },
  "bytes": { "up": 0, "down": 0 },
  "refused": { "cover_served": 1180, "not_found": 41, "bad_token": 0, "session_limit": 0 }
}
```

Read it like this:

| Pattern | Cause |
|---|---|
| `cover_served` climbing, `created` flat | nothing is recognised: wrong hostname, wrong secret form, or a secret set the relay has not reloaded |
| `created` climbing, `attached` flat, `not_found` climbing | the client's address cannot be resolved, so the WebSocket is refused — a PROXY-protocol or `X-Forwarded-For` problem |
| `created` and `attached` climbing, `streams.opened` flat | the backend cannot be dialled: the proxy is down, the `[[listener]]` did not bind, or the port is wrong |
| `session_limit` non-zero | you are at `max-sessions`; this is capacity, not abuse |
| nothing moves at all | the front proxy never reached the relay, or the relay refused the connection before HTTP — see [PROXY protocol](#proxy-protocol-in-both-directions) |

Some `cover_served` is normal on a public hostname; it is the internet knocking. What
matters is a sudden climb alongside users reporting failures.

**6. Everything else.** The WEB connection type arrived in Telegram Desktop 7.1, and
7.1.0 and 7.1.1 carried a WebView2 bug that broke some WEB proxies on Windows — so 7.1.2
is the floor, and anything older than 7.1 has no WEB proxy field at all. A service worker
already covering `/` on that hostname intercepts the navigation before the client's own
page loads. And the vhost must send *everything* to the relay, including `/api/v1/*` —
splitting it between the front proxy and the relay hands a prober a timing and
header-order difference between two components' 404s.

Be aware of what has actually been tested: Telegram Desktop 7.1.2 on Windows, end to end
through Caddy. The other client platforms have not been through the acceptance checklist,
and the `tg://webproxy` deep link's parameter names follow `tg://proxy` by analogy and
are not confirmed against a real client. Treat the hostname and secret that
`mtg-proxy access` prints as the reliable way to configure a client, and see
[[WEB-Proxy-Setup]].

## The relay serves the cover site to real users

A user who was working stops working, and reports a website where the app used to be.
From their side this is indistinguishable from the censorship the relay exists to get
around, so it is worth being systematic.

**Cause 1: the user is not in the file.** The relay reads the config file and nothing
else. It watches that file and applies a changed `[secrets]` table by itself within a
few seconds — so a user who *is* in the file is known to the relay without anyone
sending anything. A user added through the proxy's management API and never written to
the file is not, and their link is answered by the cover site. Write the file. To apply
a change immediately rather than on the next look:

```bash
systemctl reload mtg-proxy-web-relay
```

```bash
kill -HUP "$(pidof mtg-proxy-web-relay)"
```

No unit file ships in the repository, so the name above is only the one used in the
project's own examples — substitute whatever you called yours. For `systemctl reload` to
work at all, the unit needs `ExecReload=/bin/kill -HUP $MAINPID`. Windows builds have no
SIGHUP; the file watcher is the only trigger there.

**Cause 2: the reload was refused.** Every refusal is a warning in the relay's log and a
tick on `reload_failures`:

```bash
curl -sS http://127.0.0.1:8100/stats | jq '{reloads, reload_failures, last_reload, profiles}'
```

If `reload_failures` moved and `last_reload` did not, a reload — the relay's own look at
the file, or your signal — found the file and rejected it. The log says which, and
`trigger=file` or `trigger=signal` says whose:

- `web relay reload: cannot read the config, keeping the current profiles` — the file
  does not parse, or the path changed. The watcher leaves a file alone until it has held
  still across two looks, so from `trigger=file` this means the *finished* file is broken;
  from `trigger=signal` it may only mean the signal landed mid-write.
- `web relay reload: the config is unusable, keeping the current profiles` — it would not
  pass `--check`.
- `web relay reload: [web] changed in a way that needs a restart, profiles left
  unchanged` — you changed the host, the bound address, the backend, the token key, the
  cover site, the limits, the stats address, or the backend listener's `proxy-protocol`.
  Only the profile set is reloadable; the rest is refused whole rather than half-applied.
  Restart the relay. The refusal is logged and counted once, not again on every look at
  the file.

In every one of those the relay keeps the profile set it already had, on purpose. A relay
that emptied its registry because someone saved a broken file would serve the cover site
to *every* user while reporting nothing wrong.

**Cause 3: the hostname changed.** Then every capability ever issued is invalid at once
and every user gets the cover site simultaneously. `cover_served` climbs hard,
`sessions.created` stays flat. Re-issue links with `mtg-proxy access`.

**Cause 4: the token key was replaced.** Rotating it invalidates every live session.
`generate-web-key` refuses to overwrite an existing file precisely so this cannot happen
by running a command twice.

To confirm the cover site is being served rather than something else failing, check that
an unrecognised request and a plain request are byte-identical:

```bash
diff <(curl -sS https://web.example.com/) <(curl -sS 'https://web.example.com/?bridge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
```

No output is the correct answer, and also confirms the relay is up and reachable.

## PROXY protocol, in both directions

This is the failure that produces the least evidence, so it gets its own section. There
are three independent settings, one per hop, and each of them is a place two components
can disagree.

| Hop | Receiver setting | Sender setting |
|---|---|---|
| load balancer to `bind-to` | top-level `proxy-protocol-listener` | the balancer's own |
| front proxy to relay | `[web] client-ip` | the front proxy's, e.g. Caddy's `transport http { proxy_protocol v2 }` |
| relay to proxy | `[[listener]] proxy-protocol` | derived — the relay reads the same stanza |

The last hop is derived rather than configured twice, and that is the design: two places
to say it are two places to disagree, and the disagreement is invisible.

**A header nobody is expecting** is the silent one. The receiving listener has
`proxy-protocol = false`, the sender emits a header anyway, and those bytes are consumed
as the first bytes of the client's obfuscated handshake. Every stream then fails at the
same offset. On a `[[listener]]` the connection takes the ordinary refusal path, so it
shows up only as `obfuscated.misses` and `obfuscated.denied` climbing on `/stats`:

```bash
curl -sS http://127.0.0.1:9090/stats | jq '.obfuscated'
```

If `trials` and `misses` climb together and no user ever connects, suspect this before
suspecting the secrets. On `bind-to` the same mistake corrupts the ClientHello instead,
so the connection is fronted and there is no counter at all — only `cannot read client
hello` with `debug = true`.

**An expected header that never arrives** behaves differently on each side, and you need
to know which:

- On the **proxy** (`proxy-protocol = true` on a listener, or
  `proxy-protocol-listener = true`) it is not an error. The underlying library's default
  policy serves the connection anyway and attributes every client to the immediate peer.
  Behind a loopback carrier that means every user is `127.0.0.1`: the blocklist and the
  allowlist stop matching anything real, every log line names the loopback, and nothing
  says so. On a *public* listener it is worse, because `handshakes-per-ip` is armed there
  — one shared bucket for everybody, which anyone can empty for every legitimate user.
- On the **relay origin** (`client-ip = "proxy-protocol"`, the default) it is refused.
  The connection never becomes an HTTP request, so no counter moves and the front proxy
  reports a gateway error. That is deliberately loud — a front proxy configured without
  `proxy_protocol` should fail on its first connection rather than quietly mislabelling
  every user for a month.
- With `client-ip = "x-forwarded-for"` the header is read only from a loopback peer and
  only its right-most entry. A missing header, or a peer that is not loopback, means the
  address cannot be resolved and the WebSocket gets a 404: `sessions.created` climbs,
  `sessions.attached` does not, `refused.not_found` does.

To check what the proxy actually believes about client addresses, turn on `debug` briefly
and read the `ip` field on the connection lines. Prefer that over switching on
`track-client-ips`, which is a retention decision rather than a debugging tool — see
[[Security]].

## Quota, expiry and disable refusals

One user stops connecting, everyone else is fine, and there is nothing in the log. That
is the designed behaviour: an over-quota, expired or disabled secret is routed to the
fronting domain exactly like a wrong secret, so a prober cannot tell a limited user from
an invalid one. The cost of that property is that you cannot tell either, from the
outside.

```bash
curl -sS http://127.0.0.1:9090/secrets | jq '.secrets[] | {name, quota_remaining, expires_at, disabled}'
```

`quota_remaining` at zero, an `expires_at` in the past, or `disabled: true` is your
answer. Absent fields mean no limit of that kind is set.

```bash
curl -sS -X POST http://127.0.0.1:9090/secrets/alice/reset-quota
```

Two behaviours to keep straight. Enforcement happens at connection time, so a quota
overrun never cuts an active session — a heavy user can stay online past their limit
until they reconnect. But disabling or expiring a secret does close its live connections,
on the next reload or API call.

And limits set through the API are **in-memory only**. A later `POST /reload`, or a
restart, re-reads the file and overrides them. Treat the config file as the source of
truth. Quota counters themselves survive a restart only if you set `usage-state-file`;
without it, every restart zeroes everyone's usage.

See [[Limits-and-Quotas]] for the configuration side.

## The management API does not answer

**Connection refused.** Either `api-bind-to` is unset, in which case the API server is
never started at all, or the key was swallowed by a table header above it. Check where
the key sits in the file before anything else; see
[the ordering trap](#the-config-parses-but-half-your-settings-did-nothing).

```bash
curl -sS http://127.0.0.1:9090/stats
```

**401.** `api-token` is set and the request did not carry it. The token guards every
endpoint, not only the mutating ones.

```bash
curl -sS -H "Authorization: Bearer change-me" http://127.0.0.1:9090/secrets
```

**503 on `POST /reload`.** The proxy was started with `simple-run` and has no config file
to re-read.

**`listeners` and `obfuscated` missing from `/stats`.** Neither is a fault. Both appear
only when at least one `[[listener]]` is configured, so a deployment serving `bind-to`
alone gets exactly the response it always got.

**Deciding whether a binary supports something at all.** Read `features`, which is a
sorted list of capability names and a stable contract — names are never renamed or
removed, only appended:

```bash
curl -sS http://127.0.0.1:9090/stats | jq '.features'
```

A binary that carries the WEB transport advertises `web-relay` there, even though the
proxy itself does not serve it. See [[Multi-User-and-API]] and [[Monitoring]].

## If none of this helps

Check [[FAQ]] first — several of the questions there are things that look like faults and
are not.

Then collect these before opening an issue: the output of `mtg-proxy doctor`, the output
of `mtg-proxy web-relay --check` if the WEB transport is involved, a config file with the
secrets and `api-token` removed, and a minute of log with `debug = true` around the
failure. Say which client and which version, and on which platform — the WEB transport in
particular behaves differently across the three WebView engines, and a fault that
reproduces only on one of them is a different fault.
