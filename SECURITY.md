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
