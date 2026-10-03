# One host: FakeTLS on :443, your real website behind it

mtg-proxy takes port 443. A Telegram client that holds a valid `ee` secret is
served as a proxy client. Every other TLS connection to 443 — a browser, a
crawler, a censor's probe — is handed over unchanged to a web server on
loopback, which answers with the real certificate for your domain and your real
website.

The domain resolves to this server, so the name in every client's ClientHello
matches the address it connects to. `mtg-proxy doctor` reports the SNI-DNS
match as passing, and the startup `SNI-DNS mismatch` warning goes away. Anyone
who looks at the address — passively, or by connecting to it — finds an ordinary
HTTPS website.

```
               ┌──────────────────────────────┐
 :443  ───────>│ mtg-proxy (FakeTLS)          │
               │  valid ee secret → Telegram   │
               │  anything else   → fronted ───┼──> Caddy 127.0.0.1:9443
               └──────────────────────────────┘     real cert, /var/www/cover
 :80   ───────────────────────────────────────────> Caddy (ACME, redirect to https)
```

There is no extra router: with one name on the port, mtg-proxy's own domain
fronting is the router. Use [`contrib/sni-router`](../sni-router) instead when
another service needs its **own** hostname on 443 too, such as a WEB relay
origin. A WEB relay cannot share this name: both would claim every
non-Telegram connection to it.

## What you need

- A domain or subdomain whose A (and AAAA, if you have one) record points at
  this server.
- Port 80 reachable from the internet, so Caddy can obtain and renew the
  certificate.
- Caddy with the `proxy_protocol` listener wrapper; 2.11 is what this was
  written against.
- A website: static files with `index.html` at the top. A `404.html` is used
  for missing pages if present.

## Set up

1. **Caddy.** Copy `Caddyfile` to `/etc/caddy/Caddyfile`, replace `example.com`
   in all three places, and check it:

   ```bash
   caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
   ```

2. **The site.** Install the publisher, then publish your site:

   ```bash
   install -m 0755 publish-cover-site /usr/local/bin/publish-cover-site
   tar -C ./my-site -czf site.tar.gz .
   publish-cover-site site.tar.gz
   ```

   `/var/www/cover` becomes a symlink to the live version. A site already
   there as a plain directory is kept as the oldest version, so
   `--rollback` can still reach it.

3. **The proxy.** Merge `mtg-config.snippet.toml` into your config:
   - `bind-to` becomes `:443`;
   - the `ee` secrets name your domain;
   - `[domain-fronting]` points at Caddy.

   Then validate:

   ```bash
   mtg-proxy run --check /etc/mtg-proxy/config.toml
   ```

   An existing secret keeps its key if only its hostname changes. `dd` links
   carry only the key, so they keep working; `ee` links change.

4. **Switch.** Caddy has to let go of 443 before the proxy can take it:

   ```bash
   systemctl reload caddy
   systemctl restart mtg-proxy
   ```

5. **Check.**

   ```bash
   curl -sI https://example.com/ | head -1                     # the site, real cert
   curl -sI http://example.com/x | grep -i location            # https://example.com/x, no port
   mtg-proxy doctor /etc/mtg-proxy/config.toml                 # SNI-DNS match: passing
   mtg-proxy access /etc/mtg-proxy/config.toml                 # the new links, port 443
   ```

## Publishing your website

Build the site wherever you like, then send the folder's contents. These
commands work from Linux, macOS, and Windows (PowerShell or cmd, which ship
`tar` and `ssh`):

```bash
tar -C my-site -czf site.tar.gz .
scp site.tar.gz server:/tmp/site.tar.gz
ssh server publish-cover-site /tmp/site.tar.gz
```

- **Every publish is a new version.** It is unpacked beside the live one and
  switched in with a single rename, so a visitor never sees half a site. The
  five newest versions are kept.
- **Going back:** `publish-cover-site --rollback`. `publish-cover-site --list`
  shows the versions on disk.
- **No restart.** Caddy serves whatever is live.
- **Built sites** (Hugo, Astro, Vite, Next.js static export) publish their
  output folder: `public/`, `dist/` or `out/`.
- **A single-page app** with client-side routes needs `try_files {path}
  /index.html` added to the site block. Without it, a deep link answers 404.
- **A site with a backend** — PHP, Node, anything that runs — replaces
  `root`/`file_server` with `reverse_proxy` to the app.

### What makes a good cover site

- **It looks like what the name suggests.** It should be lived-in, not a
  template that thousands of servers also serve: a starter page shared across
  deployments becomes a signature.
- **It is self-contained.** Serve fonts, scripts and images from the site
  itself. A third-party CDN may be blocked or slow where your users are, and it
  ties your site to someone else's availability.
- **It never mentions Telegram, proxies or VPNs.**

## Why the configuration is the way it is

- **`[domain-fronting]` is set explicitly.** The domain resolves to this
  server. Left to DNS, the proxy would front non-Telegram connections to
  itself, in a loop.
- **The site listens on loopback only.** Its port 9443 is never reachable from
  outside, so the only way to the site is through 443, exactly as for a
  browser.
- **The PROXY header is accepted from loopback only.** It lets Caddy see
  visitors' real addresses; nobody else may claim one. A connection without a
  header is served normally. That is how the proxy measures your site's
  certificate to size its own fake handshake (see
  [Security](../../docs/wiki/Security.md)).
- **No HTTP/3.** Caddy would advertise it on 9443, a port nobody can reach.
- **The redirect is written out**, because the automatic one would point at
  9443.
- **No access log.** The people visiting a site that fronts a proxy should not
  be written to disk.
