# Connection Types

mtg-proxy answers on three different doors. All three serve the same users, out
of the same `[secrets]` table, with the same counters and the same limits. What
changes between them is what a network sitting between the client and your
server sees, which clients can walk through, and how much work the door costs to
stand up.

- [One secret, three spellings](#one-secret-three-spellings)
- [FakeTLS — the ee door](#faketls--the-ee-door)
- [obfuscated2 — the dd and plain doors](#obfuscated2--the-dd-and-plain-doors)
- [WEB — your own hostname](#web--your-own-hostname)
- [Choosing](#choosing)
- [What the proxy reports](#what-the-proxy-reports)

| | door | secret form | what a network in between sees |
|---|---|---|---|
| **FakeTLS** | `bind-to`, normally `:443` | `ee…` | a real-looking TLS handshake to your fronting domain |
| **obfuscated2** | a `[[listener]]` | `dd…` or bare hex | a nondescript TCP stream, fingerprintable as an MTProto proxy |
| **WEB** | your own hostname over HTTPS | `dd…` | a browser loading a page and opening a WebSocket, over genuine TLS |

`bind-to` is FakeTLS and only FakeTLS, permanently. The other two doors are
additive: you open them by adding a stanza, and everything that was working
before keeps working.

## One secret, three spellings

A Telegram secret is not a string. It is a serialized structure whose useful part
is **16 random key bytes**, and those bytes are what derives every cipher, HMAC
and checksum on the connection. The prefix in front of them is a message to the
*client* about which door to knock on. It changes nothing about the cryptography
and nothing about who you are on the server.

```
ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d
|-|-------------------------------|-------------------------------------------
 p key (16 bytes)                  fronting hostname
```

The three wire forms, and the length is what tells them apart before the first
byte does:

| form | bytes | shape | carries a hostname |
|---|---|---|---|
| `plain` | 16 | a bare key | no |
| `dd` | 17 | `0xdd` + key | no |
| `ee` | 17 + hostname | `0xee` + key + hostname | yes |

So one user, `alice`, with the key `367a189aee18fa31c190054efd4a8e95`, is handed
one of these three depending on the door — and it is the same account each time:

```
ee 367a189aee18fa31c190054efd4a8e95 73746f726167652e676f6f676c65617069732e636f6d
dd 367a189aee18fa31c190054efd4a8e95
   367a189aee18fa31c190054efd4a8e95
```

(The spaces above mark the boundaries. A real secret is one unbroken hex string.)

One name in `[secrets]`, one entry in per-user stats, one quota bucket, one
expiry, one connection cap — whichever spelling the client used. Handing someone
a `dd` link does not create a second account and does not reset their counters.
Nothing has to be re-issued when you open a new door. See
[[Multi-User-and-API]] and [[Limits-and-Quotas]].

**Store secrets in `ee` form.** `mtg-proxy generate-secret` defaults to
`--mode ee`, and that is the form to keep in the config file, because
`mtg-proxy access` renders the `dd` and `plain` spellings for you at print time.
There is also a hard reason: the FakeTLS listener always exists and always needs
a cover site to front a failed handshake to, so a secret set with no `ee` member
and no `domain-fronting.host` is rejected at startup.

```bash
mtg-proxy generate-secret --hex storage.googleapis.com
```

A `[secrets]` table holding only `dd` secrets, with no `domain-fronting.host`,
fails config validation:

```
invalid config: no secret carries a fronting hostname and domain-fronting.host is unset;
the FakeTLS listener would have no cover site. Set domain-fronting.host, or keep at
least one ee secret
```

## FakeTLS — the ee door

**On the wire.** A TLS-shaped ClientHello arrives carrying your fronting domain
as SNI; the proxy answers with a matching ServerHello, and the MTProto stream
runs inside what looks like an ordinary TLS record stream. A connection that
fails the handshake is not closed — it is relayed to the real fronting site, so a
prober who guesses wrong gets a genuine website rather than a distinguisher.
Anti-replay and timestamp checks reject recorded handshakes.

**Which clients.** All of them. This is the form every modern Telegram client
should be given, and it is what `mtg-proxy generate-secret` produces by default.

**What it costs.** You need a fronting hostname that is a real, reachable HTTPS
site. It does not have to point at your server, but it has to exist, because your
proxy connects out to it to serve fronted probes. `mtg-proxy doctor` checks that
the name resolves and that the SNI-to-DNS match is sane.

```bash
mtg-proxy doctor /etc/mtg-proxy/config.toml
```

**When to use it.** By default, and for everyone, unless you have a specific
reason not to. It is the only door that needs nothing beyond a port.

```toml
bind-to = "0.0.0.0:443"

[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

One command prints the links for every door you have opened:

```bash
mtg-proxy access /etc/mtg-proxy/config.toml
```

The FakeTLS links are at the top level, under `ipv4` and `ipv6`, using the
alphabetically first secret:

```json
{
  "ipv4": {
    "ip": "203.0.113.9",
    "port": 443,
    "tg_url": "tg://proxy?port=443&secret=7jZ6GJruGPoxwZAFTv1KjpVzdG9yYWdlLmdvb2dsZWFwaXMuY29t&server=203.0.113.9",
    "tme_url": "https://t.me/proxy?port=443&secret=7jZ6GJruGPoxwZAFTv1KjpVzdG9yYWdlLmdvb2dsZWFwaXMuY29t&server=203.0.113.9"
  },
  "secret": {
    "hex": "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d",
    "base64": "7jZ6GJruGPoxwZAFTv1KjpVzdG9yYWdlLmdvb2dsZWFwaXMuY29t"
  },
  "secrets": {
    "alice": { "hex": "ee367a…", "base64": "7jZ6GJ…" },
    "bob":   { "hex": "ee0123…", "base64": "7gEjRW…" }
  }
}
```

Every link object also carries `tg_qrcode` and `tme_qrcode`, omitted here for
width; each is an `api.qrserver.com` URL wrapping the link beside it. `secrets`
appears only when more than one secret is configured. `--hex` switches these
top-level links from base64 to hex, and `--port` overrides the port in them.

## obfuscated2 — the dd and plain doors

**On the wire.** Nothing that looks like anything. There is no TLS at all: after
a 64-byte handshake frame the connection is an AES-CTR stream and no more. These
are the pre-FakeTLS forms of the protocol.

Because `bind-to` is FakeTLS-only, these live on their own socket, declared as a
`[[listener]]`. One port never serves both entry paths and there is no sniffing
between them — which door a connection came through is decided by which socket it
landed on.

```toml
[[listener]]
bind-to = "127.0.0.1:2398"
accept  = ["dd", "plain"]
```

`accept` is required and must be a non-empty subset of `{"dd", "plain"}`. `"ee"`
is rejected here:

```
listener 127.0.0.1:2398: accept must be a non-empty subset of ["dd","plain"];
the top-level bind-to serves FakeTLS and a [[listener]] never does.
Run two listeners if you need both
```

**Which clients.** The links `mtg-proxy access` prints for a listener are
ordinary `tg://proxy` and `t.me/proxy` links, so any client that takes one of
those takes these — this repository does not pin a version floor for `dd` or
plain, the way it does for WEB. What it does document is the transport each
client picks, which is why the two forms differ.

`dd` means padded-intermediate and nothing else. `plain` means all three —
padded-intermediate, intermediate and abridged — because a bare 16-byte secret
places no constraint on the client's transport: tdlib sends intermediate,
Telegram Desktop and iOS send abridged, and any of them may pick
padded-intermediate. Honouring a subset silently breaks part of the client
population, so `accept = ["dd", "plain"]` is the safe pairing when you do not
control what is arriving.

**What it costs.** A second port, and everything that comes with a plaintext one.
There is no fronting fallback: a probe cannot be handed to a cover site, because
the socket does not speak TLS and a TLS alert coming back out of a plaintext port
is worse than the reset it replaced. On a public address it is also
fingerprintable, which is what the next section is about. Domain fronting, the
SNI check and the timestamp check are all FakeTLS machinery and none of them
applies here.

### Why a public obfuscated2 port needs public = true

FakeTLS is hard to identify because it looks like TLS and behaves like a website
when probed. An obfuscated2 port has neither property. A scanner that opens it
sees a socket that speaks no known protocol, negotiates nothing, and reacts to a
wrong secret in a way that is measurable. There is no cover site to fall back to
either: the listener does not speak TLS, so relaying a probe to an HTTPS site
would pipe a TLS alert back out of a plaintext port.

That is a property of the transport, not something a setting can fix. So
mtg-proxy refuses to open one on a reachable address unless you have written down
that you understand it:

```
listener 0.0.0.0:8444 accepts [dd] on a public address. A non-FakeTLS listener
answers obfuscated2 and is fingerprintable as an MTProto proxy. Set public = true
on this [[listener]] to confirm, or bind it to 127.0.0.1
```

`public = true` is an acknowledgement, not a feature. It also arms the per-IP
failed-handshake budget, which is deliberately *not* armed on a loopback
listener: behind a local carrier every connection presents `127.0.0.1`, so one
shared bucket is something an attacker empties on behalf of every real user.

| key | type | default | meaning |
|---|---|---|---|
| `bind-to` | `host:port`, host a literal IP | required | address for this obfuscated2 listener |
| `accept` | non-empty subset of `{"dd","plain"}` | required | which secret forms this socket honours |
| `public` | bool | `false` | required on any non-loopback `bind-to`; also arms `handshakes-per-ip` |
| `proxy-protocol` | bool | `false` | expect a PROXY header on **this** listener; the top-level `proxy-protocol-listener` applies to `bind-to` only |
| `on-unknown-secret` | `"close"` or `"drain"` | `"close"` | disposal of a connection no secret matches |
| `handshakes-per-ip` | uint | `30` | per-IP failed-handshake budget per second, burst 2x; armed only when `public = true` |

`on-unknown-secret = "drain"` reads and discards instead of resetting, bounded by
8 KiB of volume and by the handshake deadline. On a public listener a socket that
neither answers nor hangs up is less distinctive than a prompt reset. On loopback,
`close` is the right answer and is the default.

**When to use it.** Two cases. Behind a WEB front-end on loopback — Telegram's
own [tproxy-server](https://github.com/telegramdesktop/tproxy-server), or
mtg-proxy's own relay — which is the intended consumer. Or, publicly, when you
have clients that will not take an `ee` secret and you have decided the
fingerprint is an acceptable trade. Prefer loopback.

### What access prints for a listener

`mtg-proxy access` grows a `listeners` array, with one link per user per accepted
form, on that listener's own port rather than `bind-to`'s:

```json
"listeners": [
  {
    "bind_to": "0.0.0.0:8444",
    "accept": ["dd", "plain"],
    "public": true,
    "ipv4": {
      "ip": "203.0.113.9",
      "port": 8444,
      "secrets": {
        "alice": {
          "dd": {
            "secret": "dd367a189aee18fa31c190054efd4a8e95",
            "tg_url": "tg://proxy?port=8444&secret=dd367a189aee18fa31c190054efd4a8e95&server=203.0.113.9",
            "tme_url": "https://t.me/proxy?port=8444&secret=dd367a189aee18fa31c190054efd4a8e95&server=203.0.113.9"
          },
          "plain": {
            "secret": "367a189aee18fa31c190054efd4a8e95",
            "tg_url": "tg://proxy?port=8444&secret=367a189aee18fa31c190054efd4a8e95&server=203.0.113.9",
            "tme_url": "https://t.me/proxy?port=8444&secret=367a189aee18fa31c190054efd4a8e95&server=203.0.113.9"
          }
        },
        "bob": { "dd": {}, "plain": {} }
      }
    },
    "ipv6": { "ip": "2001:db8::1", "port": 8444, "secrets": {} }
  },
  {
    "bind_to": "127.0.0.1:2398",
    "accept": ["dd"],
    "public": false,
    "unreachable": "bound to loopback, so it is reachable only from this host (a WEB relay backend is meant to look like this)"
  }
]
```

`bob` and the `ipv6` block are filled in exactly like `alice` and `ipv4`; they
are empty above only to keep the example readable. Every link object also carries
`tg_qrcode` and `tme_qrcode`. The whole `listeners` array is omitted when no
`[[listener]]` is configured, so a deployment that never declared one gets the
output it always got.

Note the second entry. A loopback listener gets no links and says why: that is
the shape of a WEB relay backend, not a mistake, so it is reported rather than
warned about.

Note also that alice's `dd` and `plain` secrets are her own sixteen key bytes —
the same ones inside her `ee` secret further up. Same account, same quota, same
counters.

## WEB — your own hostname

Telegram Desktop 7.1 added a **WEB proxy** connection type. The client loads a
page from a hostname you control, inside its own WebView, and that page carries
an MTProto stream over a WebSocket. On the wire it is a browser visiting a
website over ordinary HTTPS — and unlike FakeTLS, the TLS is not an imitation.

**On the wire.** A real TLS session to your certificate, a `GET /` carrying a
`bridge` query parameter, then a WebSocket upgrade on an ordinary-looking
application path. Anything that does not carry a credential the relay minted is
served by your cover site, unmodified, on every path.

**Which clients.** Telegram Desktop 7.1.2 or later. 7.1.0 and 7.1.1 had a
WebView2 bug that broke some WEB proxies on Windows. What this project has
actually taken end to end is Telegram Desktop 7.1.2 on Windows, through Caddy;
the other Desktop platforms have not been through the acceptance checklist, and
this repository makes no claim about the mobile clients. Assume a desktop
audience until you have tested otherwise.

**What it costs.** The most of the three. A hostname with a browser-trusted
certificate on port 443 (the WebView validates normally and offers no way past an
error), a front proxy terminating TLS, a second process of the same binary, a
32-byte signing key, and a plausible cover site.

The relay runs from the same config file the proxy reads:

```bash
mtg-proxy generate-web-key /etc/mtg-proxy/web.key
```

```bash
mtg-proxy web-relay --check /etc/mtg-proxy/config.toml
```

```bash
mtg-proxy web-relay /etc/mtg-proxy/config.toml
```

```toml
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
proxy-protocol = true

[web]
enabled = true
host = "web.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/srv/site"
```

Three things in there are load-bearing and easy to get wrong:

- **`backend` must name a `[[listener]]` above.** The relay reads that stanza to
  decide whether to send a PROXY header, so the two processes cannot disagree
  about what the socket between them speaks. A header the listener is not
  expecting is consumed as the first bytes of the client's obfuscated handshake:
  every stream then dies at the same offset with nothing in a log to say why.
- **`token-key` is never generated at startup.** A key invented on a missing file
  works until the first restart, and then starts handing this relay's own live
  session tokens to the cover site.
- **The cover site is required and nothing ships as a default.** Exactly one of
  `cover-dir` or `cover-upstream` must be set. A starter page that many operators
  installed would be a better signature than anything the protocol leaks, so
  there is nothing to install by accident — you supply a plausible website for
  that hostname yourself.

The relay can also serve its own counters, and that socket **must** be a loopback
address; the relay refuses to start otherwise. It answers, with no credential at
all, how many sessions are live and how many bytes have moved — exactly the
traffic analysis this transport exists to deny. It is deliberately a second
socket rather than a path on `bind-to`, because that origin is published to the
internet and a real endpoint on it would be a fingerprint however it was gated.

```toml
[web]
stats-bind-to = "127.0.0.1:8100"
```

```bash
curl http://127.0.0.1:8100/stats
```

The relay re-reads `[secrets]` on `SIGHUP` and swaps its profile set atomically;
any other change under `[web]` is refused whole with `restart required` rather
than half-applied. Windows has no `SIGHUP`, so restart the relay there.

**When to use it.** When FakeTLS is being blocked where your users are and you
have a hostname, a certificate and desktop users. It is additive: run it beside
`bind-to`, and the users who cannot use it are unaffected.

The full deployment — the Caddy vhost, the four hops that have to carry the
client's address, and the acceptance checklist — is in
[contrib/web-relay/](https://github.com/Arman2122/mtg-proxy/tree/main/contrib/web-relay).
See also [[WEB-Proxy-Setup]].

### What access prints for WEB

Two things are different from every other link on this page, and both come from
the client rather than from the proxy.

**The secret is the `dd` form.** A WEB-capable client refuses an `ee` secret
outright, before it opens a socket. So the relay re-expresses each configured
secret's key as `dd` — the same sixteen bytes, told differently — and derives its
bridge credential from that. You keep `ee` secrets in the config and nothing is
re-issued. It is `dd` rather than `plain` deliberately: `dd` makes every stream
padded-intermediate, which is the transport the ad-tag path supports.

**There is no address and no port.** The client's WEB proxy form has one field, a
hostname, and forces `https` and 443. A WEB link is therefore not tied to an IP —
and changing `host` invalidates every WEB link ever issued, because the hostname
is an input to the credential each client derives. That is the same property an
`ee` secret's fronting domain has.

```json
"web": {
  "host": "web.example.com",
  "secret": {
    "secret": "dd367a189aee18fa31c190054efd4a8e95",
    "tg_url": "tg://webproxy?secret=dd367a189aee18fa31c190054efd4a8e95&server=web.example.com"
  },
  "secrets": {
    "alice": {
      "secret": "dd367a189aee18fa31c190054efd4a8e95",
      "tg_url": "tg://webproxy?secret=dd367a189aee18fa31c190054efd4a8e95&server=web.example.com"
    },
    "bob": {
      "secret": "dd0123456789abcdef0123456789abcd95",
      "tg_url": "tg://webproxy?secret=dd0123456789abcdef0123456789abcd95&server=web.example.com"
    }
  }
}
```

Each entry also carries `tg_qrcode`, elided above. The whole `web` object is
omitted unless `[web]` has `enabled = true` and a `host`.

Only the `tg://` spelling is emitted, and there is no `tme_url` here. The client
routes both `tg://webproxy` and `t.me/webproxy`, but t.me has not registered that
route, so an `https` link resolves as the *username* `@webproxy` and shows a
stranger's contact page.

**Be honest with your users about the deep link.** The parameter names in
`tg://webproxy?…` mirror `tg://proxy`, which is the only published precedent, and
they have not been confirmed against a real client. Treat the printed `host` and
`secret` — which an operator types into the client's own two fields — as the
reliable way to configure a client, and the link as a convenience that may or may
not work.

## Choosing

Start with FakeTLS. Add a second door only for a reason you can name.

- **You want it to work for everyone, everywhere, on one port.** FakeTLS on
  `bind-to`. Stop here.
- **FakeTLS is being blocked where your users are, and they are on Telegram
  Desktop.** Add WEB. It needs a hostname, a certificate and a front proxy, and
  it is the only one of the three whose TLS is genuine.
- **You are running Telegram's own WEB front-end, or mtg-proxy's relay.** Add a
  `[[listener]]` on `127.0.0.1` with `accept = ["dd", "plain"]`. It never faces
  the internet, so there is nothing to fingerprint.
- **You have clients that will only take a `dd` or plain secret.** A
  `[[listener]]` on a public address with `public = true`, understanding that the
  port is identifiable as an MTProto proxy. Consider `on-unknown-secret = "drain"`
  there.

All three can run at once from one config and one user table. Order the file
carefully: `[[listener]]` and `[web]` are TOML tables, so every top-level key
written after them belongs to them rather than to the global scope. Put your
global keys first, then `[[listener]]` and `[web]`, then `[secrets]` last. See
[[Configuration]].

## What the proxy reports

`GET /stats` on `api-bind-to` names what each socket accepts, once at least one
`[[listener]]` exists. A deployment serving `bind-to` alone sees exactly the
response it saw before — `listeners` and `obfuscated` are omitted entirely.

```json
{
  "features": ["client-ips", "faketls", "listeners", "quota-reset", "secret-modes", "secrets-api", "web-relay"],
  "listeners": [
    { "bind": "0.0.0.0:443", "accept": ["ee"], "public": true },
    { "bind": "127.0.0.1:2398", "accept": ["dd", "plain"], "public": false }
  ],
  "obfuscated": {
    "trials": 412,
    "misses": 7,
    "denied": 7,
    "draining": 0,
    "rate_limited": 0
  }
}
```

`obfuscated` counts the trial-decryption entry: `trials` connections tried,
`misses` matched by no secret, `denied` refused for any reason, `rate_limited`
turned away by the per-IP budget, and `draining` as a live gauge of refused
connections currently sitting in a bounded drain. `features` is the sorted
capability list this build advertises — read it to tell an older binary from a
newer one without parsing a version string.

Per-user counters are keyed by secret name and are the same numbers whichever
door the user came through. If you also want to know *where* users connected
from, that is `track-client-ips`, which defaults to `false` on purpose and should
stay that way unless you have a concrete reason: this is a circumvention proxy,
and the addresses of the people using it are the most dangerous data on the box.
Read [[Security]] before turning it on. More on the endpoint in [[Monitoring]].

## See also

- [[Configuration]] — every key, with its default
- [[WEB-Proxy-Setup]] — the full WEB deployment
- [[Multi-User-and-API]] — named secrets, hot reload, the management API
- [[Security]] — what each door exposes and what it does not
- [[Troubleshooting]] — when a client will not connect
