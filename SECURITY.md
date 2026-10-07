# Security policy

## Supported versions

Only the latest tagged release is supported. This is a small project with one
maintainer; backporting to older tags is not something I can promise, and a
promise I cannot keep is worse than none.

| Version          | Supported          |
| ---------------- | ------------------ |
| Latest release   | :white_check_mark: |
| Anything earlier | :x:                |

## Reporting a vulnerability

Report privately, not in a public issue.

- GitHub: open a [security advisory](https://github.com/Arman2122/mtg-proxy/security/advisories/new)
- Email: arman.seyri@gmail.com

Please include what you did, what happened, and what you expected. A proof of
concept helps but is not required to start the conversation.

I will acknowledge within a few days and tell you plainly whether I can fix it,
how long I expect it to take, and when I intend to disclose. If I cannot fix
something, I will say so rather than leave the report open.

## Verifying a release

The people who run this proxy are, by design, people whose network is hostile
to them. A binary they cannot verify is a binary someone else can choose. Every
release therefore carries three things, and this section is the exact command
for each.

Set `VERSION` to the release without its leading `v`, and `PKG` to the archive
you want:

```console
VERSION=1.2.3
PKG=mtg-proxy-${VERSION}-linux-amd64
BASE=https://github.com/Arman2122/mtg-proxy/releases/download/v${VERSION}
```

**1. Checksums.** `mtg-proxy-<version>-checksums.txt` holds one SHA-256 line
per published asset.

```console
curl -sfLO "${BASE}/${PKG}.tar.gz"
curl -sfLO "${BASE}/mtg-proxy-${VERSION}-checksums.txt"
sha256sum -c --ignore-missing "mtg-proxy-${VERSION}-checksums.txt"
```

This catches a truncated transfer, a stale CDN object and a version mismatch.
It does **not** catch a deliberate substitution: the checksums file is served
from the same origin as the archive, so whoever can replace one can replace the
other. Which is what the next check is for.

**2. Build provenance.** Every release asset — the ten archives, the SBOM and
the checksums file itself — is covered by a signed in-toto attestation binding
it to this repository, this commit and the workflow run that produced it. It is
recorded in Sigstore's public transparency log, so it cannot be quietly
withdrawn or backdated.

```console
gh attestation verify "${PKG}.tar.gz" \
    --repo Arman2122/mtg-proxy \
    --signer-workflow Arman2122/mtg-proxy/.github/workflows/go.yml
```

`--signer-workflow` is not optional in spirit. Without it the check accepts an
attestation from *any* workflow in this repository that can mint an OIDC token,
which is a materially weaker claim than "this came out of the release build".

The container image is attested the same way:

```console
gh attestation verify oci://ghcr.io/arman2122/mtg-proxy:${VERSION} \
    --repo Arman2122/mtg-proxy \
    --signer-workflow Arman2122/mtg-proxy/.github/workflows/docker-publish.yml
```

`gh` needs no secret for a public repository; in GitHub Actions, set
`GH_TOKEN: ${{ github.token }}` on the step.

**3. SBOM.** `mtg-proxy-<version>-sbom.spdx.json` is an SPDX 2.3 document
describing the Go module graph the release was built from. Use it to answer
"is this affected?" when an advisory lands, without re-deriving the dependency
set from a tag.

### If you redistribute mtg-proxy

If you package these binaries into something else — a panel, an installer, a
distribution — please verify before you unpack, and **fail the build** when
verification fails rather than warning. An unverified `curl | tar` in a release
pipeline turns a single compromised asset into a root-owned binary on every one
of your users' servers, and neither you nor they will see it happen.

## Scope

This proxy's threat model is a network observer who wants to identify or block
Telegram traffic, and a hostile client who wants to reach something it should
not. Reports that matter most:

- anything that lets a client be distinguished from an ordinary TLS client on
  the wire, since that is the whole point of FakeTLS;
- anything that lets one user's traffic, secret or counters reach another user;
- anything reachable through the management API without its token;
- anything that turns the proxy into a relay to a destination it should refuse.

Denial of service by simply sending a lot of traffic is out of scope. So is
anything that requires the operator to already have configured the proxy
unsafely, though a report that the unsafe thing is too easy to configure is
welcome as an ordinary issue.

## Known side channels on an obfuscated listener

The `bind-to` port is FakeTLS only and is unaffected by everything below except
the last paragraph. A `[[listener]]` speaking plaintext obfuscated2 is a
different door, off by default, and recommended on loopback behind a carrier
such as tproxy-server.
These are the things we know about it and have chosen not to close. They are
documented rather than hidden, because an operator putting one on a public
address deserves to know what it gives away.

**A rate-limited peer is closed, never drained.** Every refusal on this
listener otherwise takes one exit: the 64-byte frame is read, nothing is
written back, and the connection is disposed of by `on-unknown-secret` — so an
unknown secret, an unhonoured transport, a replayed frame, a throttled user and
a disabled, expired or over-quota one are all indistinguishable from each
other. A peer that has exhausted its `handshakes-per-ip` budget is the one
exception: it is read from identically, but it is closed even where the
listener is set to `drain`. The drain is the longest hold the listener offers,
and handing it to a peer whose budget is already gone would make the budget a
slot-exhaustion lever instead of a defence — one IP could pin a worker slot for
a full handshake timeout, indefinitely. On `close`, which is the default and
the right answer on loopback, there is no difference to observe at all; `drain`
is the opt-in for a public listener, and this is its cost.

**A matched-then-denied frame returns faster than a miss.** Trial decryption
stops at the first key that decrypts the transport tag to something the
listener honours, so a frame that matches a secret and is then refused (a
replay, or a disabled, expired, over-quota or throttled user) short-circuits
the candidate loop, while a frame no secret matches runs all N candidates. The
difference is bounded by N times the per-candidate cost — one SHA-256
compression, one AES key expansion and one AES block, on the order of half a
microsecond each — so it is roughly 0.5 ms at a thousand secrets, and it is
only measurable by someone who already holds a valid secret. Closing it would
mean running every candidate on every connection, charging every legitimate
client the full miss price forever, which is the wrong default; MTProxy breaks
on match for the same reason. If it ever matters for a specific deployment, the
fix is a per-listener constant-work option, not a change to the default.

**A successful handshake is followed by a dial; a failed one is not.** This is
inherent to a proxy and is not fixable at this layer. It is the strongest
reason to keep these listeners on loopback.

**On the `bind-to` port, a refused ee hello is fronted sooner than a no-match.**
Under `enforce`, the handshake budget fronts a hello it refuses or finds
oversized at once, while a hello that matches no secret is fronted after its
scan, so the time to the first fronted byte can differ even though the bytes the
cover site receives are the same. The Security page of the wiki has the detail.
