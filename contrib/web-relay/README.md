# WEB proxy deployment

Telegram Desktop 7.1 added a **WEB proxy** connection type: the client loads a
page from your hostname inside its own WebView, and that page carries an MTProto
stream over a WebSocket. To a network in between it is a browser visiting a
website over ordinary HTTPS.

`mtg-proxy web-relay` is the server side of that transport. This directory is
how to put it in front of an existing [`sni-router`](../sni-router) deployment.

## What has to be true

- **A real hostname with a browser-trusted certificate on port 443.** The client
  performs standard TLS validation inside its WebView and offers no way to
  bypass a certificate error. FakeTLS is not merely unnecessary here, it is
  excluded — an `ee` secret is refused by the client before it opens a socket.
- **Telegram Desktop 7.1.2 or later.** 7.1.0 and 7.1.1 had a WebView2 bug that
  broke some WEB proxies on Windows.
- **The relay is the only gateway for that hostname.** Everything on it goes to
  the relay, including `/api/v1/*` and the site itself. Splitting the vhost
  between Caddy and the relay hands a prober a header-order and timing
  difference between two components' 404s, which is the whole thing the design
  is trying not to have.
- **No service worker may cover `/` on that hostname.** An existing one
  intercepts the navigation before the client's policy arrives.

## The chain

Four hops, and the client's address has to survive all four. Each arrow is a
separate setting, and if any one of them is missing the relay works perfectly
while every WEB user appears to the proxy as `127.0.0.1` — the blocklist stops
matching, the per-IP limits stop counting, and the logs name the loopback.

```
browser
  │  TLS to :443
  ▼
HAProxy            send-proxy-v2 on the web backend
  │  PROXY v2
  ▼
Caddy              proxy_protocol listener wrapper; terminates TLS
  │  PROXY v2      reverse_proxy … transport http { proxy_protocol v2 }
  ▼
mtg-proxy web-relay   [web] client-ip = "proxy-protocol"
  │  PROXY v2      because the [[listener]] says proxy-protocol = true
  ▼
mtg-proxy (MTProto)   [[listener]] proxy-protocol = true
```

The last hop is derived, not configured twice: the relay reads the same file as
the proxy and takes its decision from the `[[listener]]` stanza the `backend`
address names. A header the listener is not expecting would be consumed as the
first bytes of the client's obfuscated handshake, so every stream would die at
the same offset with nothing logged — hence one source of truth.

## Setting it up

### 1. A signing key

```bash
mtg-proxy generate-web-key /etc/mtg-proxy/web.key
```

32 bytes, mode `0600`. It is never generated at startup: a relay that invented
one would work until its first restart and then start handing its own live
clients' tokens to the cover site. Rotating it invalidates every live session.

### 2. Config additions

Add to the mtg-proxy configuration the relay and the proxy both read:

```toml
# The loopback socket the relay hands streams to. proxy-protocol is what
# carries the browser's address the last hop; without it the proxy sees the
# relay's own loopback address for every WEB user.
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
proxy-protocol = true

[web]
enabled = true
host = "web.example.com"          # the name clients type; also the certificate
bind-to = "127.0.0.1:8099"        # Caddy reaches the relay here
backend = "127.0.0.1:2398"        # must name the [[listener]] above
token-key = "/etc/mtg-proxy/web.key"
client-ip = "proxy-protocol"      # the default; the other value is x-forwarded-for

# Exactly one of these. The hostname must serve a plausible website to
# everyone who is not a Telegram client, and no default ships: a starter page
# many operators installed would be a better signature than anything the
# protocol leaks.
cover-dir = "/srv/site"
# cover-upstream = "http://127.0.0.1:8080"
```

Check it before starting anything:

```bash
mtg-proxy web-relay --check /etc/mtg-proxy/config.toml
```

### 3. HAProxy

Route the WEB hostname's SNI to Caddy — which is what the `sni-router`
configuration already does for everything that is not the FakeTLS domain. If you
list SNI names explicitly, add `web.example.com` to the web backend.

### 4. Caddy

Add the vhost from [`Caddyfile.snippet`](Caddyfile.snippet). The three lines that
are easy to leave out, and what each one costs:

- `transport http { proxy_protocol v2 }` — without it the relay sees Caddy's
  loopback address and refuses every stream, because there is deliberately no
  fallback to the socket's own peer.
- `log { output discard }` — the session bearer travels inside
  `Sec-WebSocket-Protocol`. An access log on this vhost writes live credentials
  to disk.
- `reverse_proxy` for `*`, not for a path prefix — see "the only gateway" above.

### 5. Hand out links

```bash
mtg-proxy access /etc/mtg-proxy/config.toml
```

The `web` object carries the hostname and each client's secret in the **dd**
form, which is the only one a WEB client accepts. The `tg://webproxy` deep link
is emitted for convenience; its parameter names follow `tg://proxy` and are not
confirmed against a real client, so the hostname and secret are printed
separately for the client's own two fields.

Changing the hostname invalidates every WEB link ever issued — the capability is
derived from it — exactly like changing an `ee` secret's fronting domain.

### 6. Adding and removing clients

The relay reads the same config file as the proxy, and it **watches** it: a
changed `[secrets]` table is applied by itself, within a few seconds of the
write settling. Add or remove a client in the file and there is nothing to
send. To apply a change immediately rather than on the next look, **SIGHUP**:

```bash
kill -HUP "$(pidof mtg-proxy-web-relay)"
```

Under systemd, put it in the unit so `systemctl reload` works:

```ini
ExecReload=/bin/kill -HUP $MAINPID
```

Only the file counts. A client added through the proxy's management API and
never written to the file is unknown to the relay, and that client's WEB link is
answered by the cover site — which, from their side, is indistinguishable from
the censorship this relay exists to get around.

A reload only ever swaps the profile list. If anything else in `[web]` changed —
the hostname, the bound address, the backend, the token key, the cover site, the
limits — or if the backend listener's `proxy-protocol` setting changed, the
relay logs that a restart is required and keeps running with what it has. It
also keeps what it has if the file is unreadable, fails validation, or would
leave it with no usable profile, so a half-written file cannot take a working
relay off the air. A file it refused is refused once, not again on every look.

Live sessions are not disturbed by a reload. Revoking a client is enforced by
the proxy, which closes their connections when *it* reloads; the relay only
gates the front door.

Windows builds have no SIGHUP. The watcher is the only trigger there, and it is
enough.

## Verifying it

Everything below can be checked from a shell. What it cannot tell you is whether
a real Telegram client connects; see the checklist at the end.

```bash
# The site looks like a site.
curl -sS https://web.example.com/ | head

# A wrong capability is byte-identical to the site.
diff <(curl -sS https://web.example.com/) \
     <(curl -sS 'https://web.example.com/?bridge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')

# The API paths are the site too, until something authentic arrives.
curl -sS -o /dev/null -w '%{http_code}\n' https://web.example.com/api/v1/session

# The WebSocket upgrade survives whatever Caddy negotiated.
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  https://web.example.com/api/v1/ws
```

The first three should be indistinguishable from a plain website. The last
should be the site's own answer as well, because that request carries no
credential.

## The acceptance checklist

None of the tests in this repository can tell you the client will connect, and no
amount of them can. What settles it is a real Telegram Desktop 7.1.2+ pointed at
a real deployment, on every platform you sell to — WebView2 on Windows, WKWebView
on macOS, WebKitGTK on Linux are three different engines running the same page.

- [ ] The cover page renders in an ordinary browser and looks like a site.
- [ ] `GET /` with no `?bridge=`, and with a wrong one, are byte-identical to it.
- [ ] The client reaches **Connected**, chats load, and **media** loads.
- [ ] On an ad-tagged secret, the **sponsored channel appears**.
- [ ] The session survives more than two minutes idle.
- [ ] The client log contains **zero** `bad SHA256 hash after aesDecrypt` over an
      hour of use.
- [ ] The proxy log shows the **browser's real address**, not `127.0.0.1`, and a
      blocked address is rejected.
- [ ] Killing the WebSocket produces the client's own retry ladder, then its
      "Open browser" fallback, and that fallback then works.
- [ ] Windows, macOS and Linux each do all of the above.

The last one is not padding. The failure this transport has is a page that works
everywhere you tested and does nothing inside one client's WebView, presenting
as "connecting…" forever with the only diagnostic in a log the user will not send
you.
