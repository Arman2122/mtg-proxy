<!--
Thanks for sending this.

If it is a one-line typo fix, delete everything below and just say so — the
checklist is for changes that touch behaviour, not for obvious corrections.
-->

## What this changes

<!-- What the code does differently now, and why that is worth doing. -->

## Why

<!--
The reason, not the restatement. What was wrong or missing, and what a user or
operator can do now that they could not before.
-->

## How it was tested

<!--
What you actually ran, and what a failure would have looked like. "Tests pass" is
not this; "I reverted the fix and the new test failed at index 4" is.
-->

---

### Checklist

- [ ] `mise run lint` is clean (or `golangci-lint run ./...` — CI pins the version, so a
      different local one can disagree)
- [ ] `go test ./... -race -count=2` passes — CI runs `-count=2`, and a concurrency test that
      only passes on the first iteration will fail there
- [ ] New behaviour has a test that **fails without the change**. If you cannot make it fail,
      say so in the PR and explain why
- [ ] If you touched `internal/webrelay/page/bridge.js`, the browser harness passes:
      `go test ./internal/webrelay/page/ -run TestBridgeInABrowser`
      (see [test/webbridge/README.md](../test/webbridge/README.md) for the one-time setup)

### If this touches configuration or the API

- [ ] The key is in **both** halves of the config: the TOML mirror in `internal/config/parse.go`
      and the public struct in `internal/config/config.go`. A mismatched `json:` tag between
      them is silent — the value parses and is then dropped
- [ ] `example.config.toml` documents it, above the first table header if it is a global key
- [ ] Nothing existing was renamed or removed. Release asset names, config keys and the
      management API are contracts that other software depends on — additive only, unless
      this PR is explicitly a breaking change and says so here

### If this adds a field to `[web]`

- [ ] You decided whether changing it is a **reload** or a **restart**, put it in
      `webStructure`, and updated the reflection guard in `run_web_relay_reload_test.go`.
      The guard will fail until you do, which is the point

### Security

- [ ] No secret, token or client address is written to a log, a persisted file, or an error
      message. `Config.String()` redacts; check anything new goes through it
- [ ] The default `accept-modes` is still `["ee"]`
- [ ] If this adds a listening socket, it is either loopback or its exposure is a documented,
      deliberate decision
