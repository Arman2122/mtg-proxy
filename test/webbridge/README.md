# Bridge-page harness

The only test in this repository that runs the WEB proxy bridge in a real
browser engine.

It exists because every other kind of test passes against a page the Telegram
client cannot run. The bridge executes inside the client's WebView under a
Content-Security-Policy the client injects at document start, with storage,
workers and half the platform shimmed away. A page that violates any of that
does not raise an error — it sits on "connecting" forever, on one platform, and
the only diagnostic is in a client log the user will not send you.

## Running it

```bash
npm install && npx playwright install chromium-headless-shell
```

Then `go test ./internal/webrelay/page/` picks it up automatically. Without
`node_modules` the Go test skips; with a browser Playwright cannot launch, the
harness exits 2 and the Go test skips with a message saying so. Only a real
assertion failure fails the build.

To drive a browser you already have, set `MTG_BROWSER_EXECUTABLE` to its
binary. Playwright is version-matched to its own download, so this is an escape
hatch for a development machine, not what CI should do.

## What it asserts

The HTML is not written here. Go renders the real document and passes it in a
fixture, so the harness cannot drift from what ships.

The client's own document-start policy is applied as a **second**
`Content-Security-Policy` header rather than replacing ours. Two policies
intersect, which is exactly what the client does to us, and it is the only way
to catch a directive the page relies on that the client denies.

| Scenario | Why it is here |
|---|---|
| Init message shape and nonce echo | The one message whose exact form the client checks before it will talk at all |
| URL scrubbed of capability and nonce | A screenshot or crash dump must not carry the credential |
| Missing nonce attaches nothing | Without an authenticated boundary the bridge must stay silent, not open a session anything could drive |
| HELLO becomes the session body verbatim | The bridge's own retry depends on repeating it byte for byte |
| WELCOME forwarded, then the socket opens | The client may create streams only after WELCOME, and the spec puts it in the HTTP response |
| One complete frame per message | The injected boundary's only downlink rule, whatever batching the relay chose |
| Uplink forwarded unchanged | The bridge never interprets DATA |
| Socket loss reports `failed` then `close` | The websocket carrier does not resume; `close` is what starts the client's retry ladder |
| A client `close` releases the session | Ignoring it orphans a relay session until the idle grace reclaims it |
| A control value accepted as an object too | The Desktop boundary does not publish whether control values arrive as JSON text or parsed objects |
| A truncated downlink batch is terminal | The boundary contract is one *complete* frame per message |
| Zero CSP violations across a full session | The failure this whole file exists for |

## What it cannot tell you

It is not a real client. It proves the page is well-formed, survives the
policy, and speaks the protocol the relay implements — it cannot prove Telegram
Desktop's WebView agrees, because that WebView is not this browser and its
injected environment is only documented for Android and iOS.

The remaining unknowns are listed as INTEROP items in the phase-2 notes: whether
Desktop injects its own CSP at all, and whether it wants control values as JSON
strings or parsed objects. Both are settled only by pointing a real client at a
real deployment.
