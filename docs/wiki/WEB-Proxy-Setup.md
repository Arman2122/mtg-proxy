# WEB Proxy Setup

Telegram Desktop 7.1 added a **WEB proxy** connection type. The client loads a page from your hostname inside its own WebView, and that page carries an MTProto stream over a WebSocket. To a network in between, it is a browser visiting a website over ordinary HTTPS — the TLS is real, not an imitation, so there is no obfuscated2 handshake to fingerprint and no FakeTLS to distinguish.

`mtg-proxy web-relay` is the server side of that transport. It is a **second process of the same binary**, reading the same configuration file as the proxy.

**Only Telegram Desktop supports this transport today.** Android, iOS, the web clients and tdlib-based clients do not offer a WEB proxy field at all. Everyone else uses FakeTLS or an obfuscated2 listener — see [[Connection-Types]].

On this page:

- What you need before you start
- The chain, and which hop carries the client address
- Setting it up
- Handing out links
- Adding and removing users
- Verifying it
- The relay's own counters
- What has and has not been tested

## What you need before you start 🌐

- **A real hostname with a browser-trusted certificate on port 443.** The client performs standard TLS validation inside its WebView and offers no way to bypass a certificate error. FakeTLS is not merely unnecessary here — it is excluded. A WEB-capable client refuses an `ee` secret before it opens a socket, so these links use the `dd` spelling of the same sixteen key bytes.
- **Telegram Desktop 7.1.2 or later.** 7.1.0 and 7.1.1 had a WebView2 bug that broke some WEB proxies on Windows.
- **The relay is the only gateway for that hostname.** Everything on it goes to the relay: the site, `/api/v1/*`, the 404s. Splitting the vhost between your front proxy and the relay hands a prober a header-order and timing difference between two components' answers, which is exactly the distinguisher the relay's recognition rule exists to remove.
- **No service worker may cover `/` on that hostname.** An existing one intercepts the navigation before the client's own policy arrives.
- **A cover site.** The hostname must serve a plausible website to everyone who is not a Telegram client. Nothing ships as a default; see [Step 4](#step-4--the-cover-site).

## The chain, and which hop carries the client address 🔗

Three hops in a standalone Caddy deployment, and the browser's address has to survive all of them. Each arrow is a separate setting. If any one is missing, the relay works perfectly while every WEB user appears to the proxy as `127.0.0.1` — the blocklist stops matching, the per-IP limits stop counting, and every log line names the loopback.

```
browser
  │  TLS to :443
  ▼
Caddy                 terminates TLS
  │  PROXY v2         reverse_proxy … transport http { proxy_protocol v2 }
  ▼
mtg-proxy web-relay   [web] client-ip = "proxy-protocol"  (the default)
  │  PROXY v2         because the [[listener]] says proxy-protocol = true
  ▼
mtg-proxy (MTProto)   [[listener]] proxy-protocol = true
```

The last hop is derived, not configured twice. The relay reads the same file as the proxy and takes its PROXY-protocol decision from the `[[listener]]` stanza its `backend` address names. A header the listener is not expecting would be consumed as the first bytes of the client's obfuscated handshake, so every stream would die at the same offset with nothing logged — hence one source of truth.

There is deliberately **no fallback** to the socket's own peer address. Behind a front proxy that peer is loopback for every user alive, so a relay that fell back would quietly disable the blocklist and the per-IP limits while appearing to work. A connection whose client cannot be identified is refused instead: the relay's listener uses `REQUIRE`, not the permissive default, so a front proxy configured without `proxy_protocol` fails loudly on the first connection.

If you already run the `contrib/sni-router` stack, HAProxy sits in front of Caddy and there are four hops; HAProxy's web backend needs `send-proxy-v2` and Caddy needs the `proxy_protocol` listener wrapper on its own port. That deployment ships as `contrib/web-relay/Caddyfile.snippet` and `contrib/web-relay/compose.web.yml`.

## Setting it up

### Step 1 — the signing key

```bash
mtg-proxy generate-web-key /etc/mtg-proxy/web.key
```

32 bytes, created with mode `0600`, and the command refuses to overwrite an existing file. The relay never generates one at startup: a key invented on a missing file would work until the first restart, after which the relay would stop recognising its own live clients' tokens and start handing them to the cover site. Rotating it invalidates every live session.

The relay also refuses to start if the file is readable by group or other. That check is skipped on Windows, where ACLs are not a permission triple.

### Step 2 — the listener and the `[web]` table

Both blocks go in the config file the proxy already reads. `[[listener]]` and `[web]` are TOML tables, so every top-level key written after them belongs to them — put both just above `[secrets]`, and `[secrets]` last.

```toml
# The loopback socket the relay hands streams to. proxy-protocol is what carries
# the browser's address the last hop; without it every WEB user is 127.0.0.1 to
# the proxy, with nothing in a log to say so.
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
proxy-protocol = true

[web]
enabled = true
host = "web.example.com"          # the name clients type; also the certificate
bind-to = "127.0.0.1:8099"        # where the front proxy reaches the relay
backend = "127.0.0.1:2398"        # must name the [[listener]] above
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/srv/site"           # or cover-upstream = "http://127.0.0.1:8080"
stats-bind-to = "127.0.0.1:8100"  # optional, loopback only, new in v1.3.0
```

The listener is not given `public = true`, and does not need it: `public` is required only on a non-loopback `bind-to`, where it is your acknowledgement that the port answers obfuscated2 in the clear and is fingerprintable as an MTProto proxy. A WEB relay backend is meant to be loopback, so there is nothing to acknowledge.

The listener must accept `dd`, because that is the only form a WEB client can hold; `accept = ["dd", "plain"]` also lets the same socket serve Telegram's own `tproxy-server` if you ever put one in front. This is a separate socket from the top-level `bind-to`, which serves FakeTLS (`ee`) only — there is deliberately no way to make `bind-to` answer `dd` or `plain`.

The `[web]` keys:

| key | default | meaning |
|---|---|---|
| `enabled` | `false` | the relay refuses to start without it |
| `host` | *required* | bare hostname, no scheme, port, IP literal or single label. Every capability is derived over it |
| `bind-to` | *required* | where the relay listens for the front proxy |
| `backend` | *required* | must name a `[[listener]]` that accepts `dd` |
| `token-key` | *required* | path from `generate-web-key` |
| `cover-dir` / `cover-upstream` | *required, exactly one* | the cover site |
| `client-ip` | `proxy-protocol` | the other value is `x-forwarded-for` |
| `stats-bind-to` | *off* | loopback address for the relay's own counters |
| `max-sessions` | `1024` | concurrent carrier sessions in one process |
| `max-streams` | `512` | logical connections inside one session |
| `max-frame-payload` | `1mib` | ceiling; may only be lowered |
| `carrier-batch-bytes` | `2mib` | ceiling; may only be lowered |

The last two are ceilings compiled into the client as well. The client learns nothing about them from the handshake, so raising one breaks interop silently while lowering one stays interoperable. Leave them alone unless you have a specific reason — the published one is a deployment still serving Linux Desktop builds from before the 2 MiB message cap.

`stats-bind-to` **must** be a loopback IP address, and the relay refuses to start otherwise. That socket answers, with no credential at all, how many sessions the relay is carrying and how many bytes it has moved — which is the traffic analysis this whole transport exists to deny. A hostname is refused too, because a name could resolve somewhere else tomorrow. It is a second socket rather than a path on `bind-to` for the same reason: `bind-to` is published to the internet, and anything there that answers differently from the cover site is a fingerprint no matter how it is gated.

The proxy ignores the whole `[web]` table, so a broken one cannot take the MTProto port down. Older binaries ignore it too, since parsing does not reject unknown keys.

### Step 3 — check it

```bash
mtg-proxy web-relay --check /etc/mtg-proxy/config.toml
```

This validates and exits, printing the host, the bound address, the backend, the profile count and the resolved `client-ip` source. It runs exactly the validation a reload runs, so anything `--check` refuses can never be applied to a running relay.

### Step 4 — the cover site

Everything arriving without a credential the relay minted gets the cover site — on every path, including the API ones. There is no shipped default, and that is a decision rather than an omission: a starter page many operators installed would become the signature, and the body, asset set and response timing of "the thing relay operators serve" is a far better distinguisher than anything the protocol leaks.

Two ways to provide it:

- `cover-dir = "/srv/site"` serves a directory. Directory listings are always off — a directory with no `index.html` is a 404, exactly as on an ordinary web server, because Go's own listing markup is recognisable at a glance.
- `cover-upstream = "http://127.0.0.1:8080"` reverse-proxies a real application. Method, path, query, headers and body travel unchanged, and no `X-Forwarded-*` set is added, because a header that appears only on this deployment is one more thing to tell it apart by. An upstream that is down produces a plain `502`.

Whichever you pick, open the hostname in an ordinary browser and ask whether it looks like a website someone would run.

### Step 5 — Caddy

A complete standalone Caddyfile, where Caddy owns port 443 for this hostname:

```caddyfile
{
	email admin@example.com
}

web.example.com {
	# The bearer for a live session travels inside Sec-WebSocket-Protocol, so an
	# access log on this vhost writes live credentials to disk. Discard it here
	# rather than filtering it: a filter is one upgrade away from being wrong.
	log {
		output discard
	}

	# `*`, not a path prefix. Everything on this hostname is the relay's,
	# including /api/v1/* and the 404s.
	reverse_proxy 127.0.0.1:8099 {
		transport http {
			# Without this the relay sees Caddy's loopback address and refuses
			# every stream, because there is deliberately no fallback.
			proxy_protocol v2

			# A carrier lives far longer than any ordinary response, and
			# surviving an idle period is an acceptance criterion.
			read_timeout 0
			write_timeout 0
		}
	}
}
```

Three lines are easy to leave out and each costs something: `proxy_protocol v2` (every stream refused), `log { output discard }` (live session bearers written to disk), and `reverse_proxy` for the whole vhost rather than a path prefix (a prober can tell the two components apart).

If the proxy also serves FakeTLS on port 443 of the same address, Caddy and the proxy cannot both own it — put an SNI router in front, as `contrib/sni-router` does, or give each its own address. See [[Installation]].

### Step 6 — systemd units

No unit files ship in the repository; these are a starting point. Write them to `/etc/systemd/system/`.

`mtg-proxy.service`:

```ini
[Unit]
Description=mtg-proxy (MTProto)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mtg-proxy
Group=mtg-proxy
ExecStart=/usr/local/bin/mtg-proxy run /etc/mtg-proxy/config.toml
# The proxy has no SIGHUP handler: its reload is the API endpoint on
# api-bind-to. Drop this line if you have not set api-bind-to.
ExecReload=/usr/bin/curl -fsS -X POST http://127.0.0.1:9090/reload
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# Only if usage-state-file is set.
ReadWritePaths=/var/lib/mtg-proxy

[Install]
WantedBy=multi-user.target
```

`mtg-proxy-web-relay.service`:

```ini
[Unit]
Description=mtg-proxy WEB relay
After=network-online.target mtg-proxy.service
Wants=network-online.target

[Service]
Type=simple
User=mtg-proxy
Group=mtg-proxy
# A file that would not validate fails the start instead of the first client.
ExecStartPre=/usr/local/bin/mtg-proxy web-relay --check /etc/mtg-proxy/config.toml
ExecStart=/usr/local/bin/mtg-proxy web-relay /etc/mtg-proxy/config.toml
# The relay follows the file by itself; this makes `systemctl reload` do it now.
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Two things about the relay unit. Use a **fixed** `User=`, not `DynamicUser=`: the token key must be mode `0600` and owned by the account the relay runs as, and a dynamic uid cannot own it across restarts. And `After=` rather than `Requires=`: if the proxy restarts, the relay should stay up serving the cover site rather than disappearing from the internet in sympathy.

```bash
systemctl daemon-reload
```

```bash
systemctl enable --now mtg-proxy.service mtg-proxy-web-relay.service
```

## Handing out links

```bash
mtg-proxy access /etc/mtg-proxy/config.toml
```

The `web` object appears whenever `[web] enabled = true` and a host is set. Trimmed to the parts that matter here:

```json
{
  "web": {
    "host": "web.example.com",
    "secret": {
      "secret": "dd367a189aee18fa31c190054efd4a8e95",
      "tg_url": "tg://webproxy?secret=dd367a189aee18fa31c190054efd4a8e95&server=web.example.com",
      "tg_qrcode": "https://api.qrserver.com/v1/create-qr-code?data=…"
    },
    "secrets": {
      "alice": { "secret": "dd367a…", "tg_url": "tg://webproxy?…" },
      "bob":   { "secret": "dd91be…", "tg_url": "tg://webproxy?…" }
    }
  },
  "listeners": [
    {
      "bind_to": "127.0.0.1:2398",
      "accept": ["dd", "plain"],
      "public": false,
      "unreachable": "bound to loopback, so it is reachable only from this host (a WEB relay backend is meant to look like this)"
    }
  ]
}
```

Four things are different from every other link this command prints, and all of them come from the client:

- **The secret is the `dd` form.** A WEB-capable client refuses an `ee` secret outright, before any network activity. It is the same sixteen key bytes spelled differently, so nothing is re-issued and the user keeps one name, one quota bucket and one set of counters. See [[Multi-User-and-API]].
- **There is no address and no port.** The client's WEB form has a single field, a hostname; it fixes the scheme to `https` and the port to 443. Changing `host` invalidates every WEB link ever issued, because the capability is derived over it — exactly like changing an `ee` secret's fronting domain.
- **Only `tg://` is emitted, not `t.me`.** The client routes both, but `t.me` has not registered the `webproxy` route, so an `https` link resolves as the username `@webproxy` and shows a stranger's contact page.
- **The deep link's parameter names are not confirmed.** They mirror `tg://proxy`, which is the only published precedent, and have not been checked against a real client. The `host` and `secret` fields above are what you type into the client's own two fields, so hand those over if the link does not take.

The `listeners` array reports the backend as `unreachable`, with the reason. That is not a misconfiguration — a loopback listener has nothing to advertise, and a WEB relay backend is supposed to look exactly like that. Per-listener links (new in v1.3.0) are for the listeners you actually expose.

## Adding and removing users

The relay reads the same `[secrets]` table as the proxy, and it **watches the file**: a change is applied by itself within a few seconds of the write settling. Add a user to the file and there is nothing to send. To apply it immediately rather than on the next look, **SIGHUP**:

```bash
systemctl reload mtg-proxy-web-relay
```

Or without systemd:

```bash
kill -HUP "$(pidof mtg-proxy-web-relay)"
```

**The proxy still has to be told.** It does not watch the file and does not handle SIGHUP; its reload is the endpoint on `api-bind-to`:

```bash
curl -X POST http://127.0.0.1:9090/reload
```

The file is the only thing the relay reads. A client added through the proxy's management API and never written to the file is unknown to the relay, and that client's WEB link is answered by the cover site — which, from their side, is indistinguishable from the censorship this relay exists to get around. Write the file.

What a reload does and does not do:

- Only the **profile set** is swapped, atomically. Live sessions are not disturbed.
- Any other change under `[web]` — the host, the bound address, the backend, the token key, the cover site, the stats address, the limits — or a change to the backend listener's `proxy-protocol`, is refused **whole**: the relay logs that a restart is required and keeps running with what it has. Applying half of a changed file is how a process ends up in a state no configuration describes.
- A file that is unreadable, fails validation, or would leave the relay with no usable profile is also refused, and the running set is kept. A relay that emptied its registry because someone saved a broken file would serve the cover site to every real user while reporting nothing wrong. A refused file is refused once, not again on every look, and a file that is mid-write is left alone until it holds still.
- A file change that leaves the profiles as they were — a comment, a limit, the proxy's own settings — is not a reload and is not counted as one.
- Revoking a client is enforced by the **proxy**, which closes their connections when it reloads. The relay only gates the front door.

Windows builds have no SIGHUP. The watcher is the only trigger there, and it is enough.

## Verifying it 🔍

The relay places every request into exactly one of three tiers, and the tier is a security property rather than a routing convenience:

| tier | what it is | answer |
|---|---|---|
| Exact | `GET /` with one canonical `bridge` parameter that resolves to a configured profile | the bridge page |
| Authentic but unusable | a real capability or a token this relay minted, but wrong path, wrong method, padded spelling, duplicated field, expired | a **local** uncacheable 404 |
| Unauthentic | everything else | the cover site, unaltered |

The middle tier exists to stop one specific leak. If a request carrying an operator's real capability were forwarded to a `cover-upstream`, that credential would land in a third party's access log. So the relay scans every query value, every header value and the path for anything it could have minted, and answers locally the moment it finds one — never proxying it onward.

From a shell you can only produce **tier-three** requests, and that is the tier worth confirming, because it is the one a prober sees. The tier-one and tier-two probes need a capability derived from your hostname and one of your secrets, which nothing in the CLI prints — the client derives it.

The site looks like a site:

```bash
curl -sS https://web.example.com/ | head
```

A wrong capability is byte-identical to it:

```bash
diff <(curl -sS https://web.example.com/) <(curl -sS 'https://web.example.com/?bridge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
```

The API paths are the site too, until something authentic arrives:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://web.example.com/api/v1/session
```

The WebSocket upgrade survives whatever Caddy negotiated:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' https://web.example.com/api/v1/ws
```

The `diff` must produce no output. The two status codes are whatever your cover site returns for an unknown path — the point is that they are the cover site's answer, not the relay's, because neither request carries a credential.

Then confirm the client's address is actually arriving. Connect a real client, and check that the proxy's log and `/stats` name the browser's address rather than `127.0.0.1`. Per-user addresses on `/stats` need `track-client-ips`, which is **off by default and should stay off unless you have a reason**: this is a circumvention proxy, and the answer to "who connected from where" is also the answer whoever takes the server gets. See [[Security]] and [[Monitoring]] before turning it on.

## The relay's own counters

With `stats-bind-to` set, the relay serves one path on that loopback socket:

```bash
curl -sS http://127.0.0.1:8100/stats
```

```json
{
  "started_at": "2026-09-04T10:00:00Z",
  "uptime_seconds": 3600,
  "profiles": ["alice", "bob"],
  "reloads": 2,
  "reload_failures": 0,
  "last_reload": "2026-09-04T10:42:00Z",
  "sessions": { "active": 7, "created": 41, "attached": 39, "max": 1024 },
  "streams": { "active": 22, "opened": 310 },
  "bytes": { "up": 18234112, "down": 401228800 },
  "refused": { "cover_served": 1043, "not_found": 2, "bad_token": 0, "session_limit": 0 }
}
```

This is what makes tiers one and two observable without a credential of your own. Watch the numbers while a real client connects:

- `sessions.created` and `sessions.attached` climbing together is tier one working end to end. `created` without `attached` is a client that got the page and never reached the socket.
- `refused.not_found` is tier two: authentic but unusable, answered locally and never forwarded.
- `refused.cover_served` is tier three. On a public hostname a non-zero number is normal — it is the internet knocking. A **sudden climb** alongside users reporting failures is the signature of a hostname or secret-set mismatch, usually a reload that did not land.
- `refused.bad_token` is a bearer naming no live session: torn down already, or a second socket trying to join a session that already has a carrier.
- `refused.session_limit` is capacity against `max-sessions`, not abuse.
- `reloads` and `reload_failures` count both the changes the relay found in the file and the SIGHUPs it was sent, and are how you tell "my SIGHUP did nothing" from "my SIGHUP was never delivered". A change that needs a restart increments `reload_failures`, once.

`bytes` are relay payload, not wire bytes — frame headers and WebSocket framing are excluded, so they compare with the proxy's own counters rather than with anything tcpdump shows.

The proxy's `/stats` advertises `web-relay` in its `features` array when the binary carries this transport. That is advertised by the proxy, which does not serve the transport, so a panel can decide whether to offer the WEB settings at all by asking the one component it always has.

## What has and has not been tested

None of the tests in this repository can tell you a real client will connect, and no number of them can. What settles it is Telegram Desktop 7.1.2 or later pointed at a real deployment, on every platform you serve — WebView2 on Windows, WKWebView on macOS and WebKitGTK on Linux are three different engines running the same page.

The acceptance checklist, from `contrib/web-relay/README.md`:

- [ ] The cover page renders in an ordinary browser and looks like a site.
- [ ] `GET /` with no `?bridge=`, and with a wrong one, are byte-identical to it.
- [ ] The client reaches **Connected**, chats load, and **media** loads.
- [ ] On an ad-tagged secret, the sponsored channel appears.
- [ ] The session survives more than two minutes idle.
- [ ] The client log contains zero `bad SHA256 hash after aesDecrypt` over an hour of use.
- [ ] The proxy log shows the browser's real address, not `127.0.0.1`, and a blocked address is rejected.
- [ ] Killing the WebSocket produces the client's retry ladder, then its "Open browser" fallback, and that fallback then works.
- [ ] Windows, macOS and Linux each do all of the above.

The last item is not padding. The failure mode this transport has is a page that works everywhere you tested and does nothing inside one client's WebView, presenting as "connecting…" forever, with the only diagnostic in a log the user will not send you.

**What has actually been tried:** Telegram Desktop 7.1.2 on Windows, end to end through Caddy, with FakeTLS and WEB both working from the same config, and the `tg://webproxy` link opening the client's WEB proxy form with the hostname and secret filled in (confirmed 2026-09-07). macOS and Linux clients have not been through the checklist. The printed hostname and `dd` secret configure a client by hand where a link cannot be opened.

If something is not working, [[Troubleshooting]] covers the common failures; [[FAQ]] and [[Configuration]] cover the rest of the file this page adds two tables to.
