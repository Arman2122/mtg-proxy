// Headless-browser harness for the WEB proxy v1 bridge page.
//
// This is the only test in the repository that runs the bridge in a real
// browser engine, and it exists because every other kind of test would pass
// against a page the Telegram client cannot run. The page executes inside the
// client's WebView under a Content-Security-Policy the client injects at
// document start, with storage, workers and half the platform shimmed away. A
// page that violates any of that does not error: it hangs on "connecting"
// forever, on one platform, with the only diagnostic in a client log nobody
// will send you.
//
// So the shape here is deliberate:
//
//   - The HTML is not written by this file. Go renders the real document and
//     hands it over in a fixture, so the harness cannot drift from what ships.
//   - The client's document-start policy is injected as a SECOND
//     Content-Security-Policy header. Two policies intersect rather than
//     replace, which is exactly what the client does to us, and it is the only
//     way to find a directive we rely on that the client denies.
//   - Every scenario counts securitypolicyviolation events and fails on any.
//
// Usage: node harness.mjs <fixture.json>

import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';

const HOST = 'proxy.example.test';
const ORIGIN = `https://${HOST}`;
const WS_URL = `wss://${HOST}/api/v1/ws`;
const SESSION_URL = `${ORIGIN}/api/v1/session`;
const NONCE = 'wZ3nS8oQd1kL2mNbVcXzAsDfGhJkLpOiUyTrEwQ8aZ0';
const SESSION_TOKEN = 'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ';

// The policy Android and iOS inject before the document runs. Desktop does not
// publish whether it injects one, so the harness assumes the strictest profile
// any client is documented to use.
const INJECTED_CSP = [
  "default-src 'none'",
  "base-uri 'none'",
  "child-src 'none'",
  `connect-src https://${HOST} wss://${HOST}`,
  "font-src 'none'",
  "form-action 'none'",
  "frame-src 'none'",
  "img-src 'none'",
  "manifest-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "script-src 'unsafe-inline'",
  "style-src 'none'",
  "worker-src 'none'",
].join('; ');

const fixture = JSON.parse(readFileSync(process.argv[2], 'utf8'));

// ------------------------------------------------------------------ framing

const HEADER_SIZE = 8;
const TYPE_DATA = 0x02;
const TYPE_HELLO = 0x10;
const TYPE_WELCOME = 0x11;

function frame(type, streamID, payload = new Uint8Array(0)) {
  const out = new Uint8Array(HEADER_SIZE + payload.length);
  out[0] = type;
  out[1] = (streamID >>> 16) & 0xff;
  out[2] = (streamID >>> 8) & 0xff;
  out[3] = streamID & 0xff;
  out[4] = (payload.length >>> 24) & 0xff;
  out[5] = (payload.length >>> 16) & 0xff;
  out[6] = (payload.length >>> 8) & 0xff;
  out[7] = payload.length & 0xff;
  out.set(payload, HEADER_SIZE);

  return out;
}

const HELLO = frame(TYPE_HELLO, 0, new Uint8Array([1]));
const WELCOME = frame(TYPE_WELCOME, 0);

function bytes(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;

  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }

  return out;
}

function hex(array) {
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ------------------------------------------------------------- assertions

let failures = 0;
let checks = 0;

function check(name, condition, detail) {
  checks += 1;

  if (condition) {
    console.log(`  ok   ${name}`);

    return;
  }

  failures += 1;
  console.log(`  FAIL ${name}${detail === undefined ? '' : ` -- ${detail}`}`);
}

function equal(name, actual, expected) {
  check(name, actual === expected, `got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
}

async function waitFor(predicate, what, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    const value = await predicate();

    if (value) {
      return value;
    }

    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }

    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

// --------------------------------------------------------------- environment

// initScript stands in for the client's own injected environment: the
// TelegramWebProxy object, the shimmed-away platform, and a recorder the
// scenarios read. It runs before the document's own script, which is exactly
// when the client installs its object.
function initScript(withHost) {
  return `(function () {
    window.__violations = [];
    window.addEventListener('securitypolicyviolation', function (e) {
      window.__violations.push(e.violatedDirective + ' ' + e.blockedURI);
    });

    window.__sent = [];
    window.__deliver = null;

    if (${withHost ? 'true' : 'false'}) {
      window.TelegramWebProxy = {
        postMessage: function (value) {
          if (value instanceof ArrayBuffer) {
            window.__sent.push({ kind: 'binary', hex: Array.from(new Uint8Array(value), function (b) {
              return b.toString(16).padStart(2, '0');
            }).join('') });
          } else {
            window.__sent.push({ kind: 'control', value: value });
          }
        },
        onmessage: null
      };

      window.__deliver = function (value) {
        window.TelegramWebProxy.onmessage(value);
      };
    }

    // The client shims these away. A page that reaches for one must fail here
    // rather than in the field.
    ['localStorage', 'sessionStorage', 'indexedDB', 'caches', 'BroadcastChannel',
     'Worker', 'SharedWorker', 'open'].forEach(function (name) {
      try {
        Object.defineProperty(window, name, {
          get: function () { throw new Error('shimmed away: ' + name); },
          configurable: true
        });
      } catch (err) { /* some are non-configurable; the getter is best effort */ }
    });
  })();`;
}

async function newPage(browser, { withHost = true, injectCSP = true } = {}) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();

  await page.addInitScript(initScript(withHost));

  const state = { sessionBodies: [], deletes: 0, wsMessages: [], socket: null, wsOpened: 0 };

  await page.route(`${ORIGIN}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'GET' && url.pathname === '/') {
      const headers = { ...fixture.headers };

      // Playwright collapses repeated header names, so the two policies are
      // joined with a comma -- which is precisely how RFC 9110 says a repeated
      // Content-Security-Policy arrives, and how a browser splits it back into
      // two independent policies that must both allow an action.
      if (injectCSP) {
        headers['content-security-policy'] = `${headers['Content-Security-Policy'] ?? headers['content-security-policy']}, ${INJECTED_CSP}`;
        delete headers['Content-Security-Policy'];
      }

      await route.fulfill({ status: 200, headers, body: fixture.html });

      return;
    }

    if (request.method() === 'POST' && url.pathname === '/api/v1/session') {
      state.sessionBodies.push(hex(new Uint8Array(request.postDataBuffer())));

      await route.fulfill({
        status: 200,
        headers: {
          'X-Session-Token': SESSION_TOKEN,
          'X-Down-Cursor': '0',
          'X-Carrier-Mode': 'websocket',
          'Cache-Control': 'no-store',
          'Content-Type': 'application/octet-stream',
        },
        body: Buffer.from(WELCOME),
      });

      return;
    }

    if (request.method() === 'DELETE' && url.pathname === '/api/v1/session') {
      state.deletes += 1;
      await route.fulfill({ status: 204 });

      return;
    }

    await route.fulfill({ status: 404, body: '' });
  });

  await page.routeWebSocket(WS_URL, (ws) => {
    state.socket = ws;
    state.wsOpened += 1;

    ws.onMessage((message) => {
      const buffer = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
      state.wsMessages.push(buffer.toString('hex'));
    });
  });

  return { context, page, state };
}

function bridgeURL(withNonce = true) {
  return `${ORIGIN}/?bridge=${fixture.capability}${withNonce ? `#android=${NONCE}` : ''}`;
}

async function violations(page) {
  return page.evaluate('window.__violations');
}

async function sent(page) {
  return page.evaluate('window.__sent');
}

async function deliver(page, value) {
  await page.evaluate((hexOrControl) => {
    if (typeof hexOrControl === 'string' && hexOrControl.startsWith('hex:')) {
      const raw = hexOrControl.slice(4);
      const out = new Uint8Array(raw.length / 2);

      for (let i = 0; i < out.length; i += 1) {
        out[i] = parseInt(raw.substr(i * 2, 2), 16);
      }

      window.__deliver(out.buffer);

      return;
    }

    window.__deliver(hexOrControl);
  }, value);
}

const controls = (records) => records.filter((r) => r.kind === 'control').map((r) => {
  const value = r.value;

  return typeof value === 'string' ? JSON.parse(value) : value;
});

const binaries = (records) => records.filter((r) => r.kind === 'binary').map((r) => r.hex);

// ---------------------------------------------------------------- scenarios

const scenarios = [];

function scenario(name, fn) {
  scenarios.push({ name, fn });
}

// The first thing the bridge does at the WebView boundary, and the one message
// whose exact shape the client checks before it will talk at all.
scenario('init message shape and nonce echo', async (browser) => {
  const { page } = await newPage(browser);
  await page.goto(bridgeURL());

  const records = await waitFor(async () => {
    const values = controls(await sent(page));

    return values.length > 0 ? values : null;
  }, 'the init message');

  const init = records[0];
  equal('init.t', init.t, 'tproxy-android-init');
  equal('init.v', init.v, 1);
  equal('init.nonce', init.nonce, NONCE);
  check('no CSP violation', (await violations(page)).length === 0, JSON.stringify(await violations(page)));
});

// The query and the fragment are replaced away before anything else happens, so
// a screenshot, a crash dump or a shared URL cannot carry the capability.
scenario('URL is scrubbed of the capability and the nonce', async (browser) => {
  const { page } = await newPage(browser);
  await page.goto(bridgeURL());

  const url = await waitFor(async () => {
    const current = await page.evaluate('window.location.href');

    return current.includes('bridge=') ? null : current;
  }, 'the URL to be replaced');

  check('no capability in the URL', !url.includes(fixture.capability), url);
  check('no nonce in the URL', !url.includes(NONCE), url);
});

// Without a nonce there is no authenticated boundary, so the bridge must stay
// silent rather than create a session anything could then drive.
scenario('a missing WebView nonce attaches nothing', async (browser) => {
  const { page, state } = await newPage(browser);
  await page.goto(bridgeURL(false));
  await page.waitForTimeout(300);

  equal('nothing sent', (await sent(page)).length, 0);
  equal('no session created', state.sessionBodies.length, 0);
});

// HELLO is the app's, not the bridge's. It must reach the relay byte-identical,
// because the bridge's own retry depends on repeating it exactly.
scenario('HELLO becomes the session body verbatim', async (browser) => {
  const { page, state } = await newPage(browser);
  await page.goto(bridgeURL());
  await waitFor(async () => (await sent(page)).length > 0, 'the init message');

  await deliver(page, `hex:${hex(HELLO)}`);
  await waitFor(() => state.sessionBodies.length > 0, 'the session request');

  equal('body is the HELLO frame', state.sessionBodies[0], hex(HELLO));
});

// WELCOME must reach the app before the socket exists: the client may create
// streams only after it sees one, and the spec puts it in the HTTP response.
scenario('WELCOME is forwarded and the socket opens', async (browser) => {
  const { page, state } = await newPage(browser);
  await page.goto(bridgeURL());
  await waitFor(async () => (await sent(page)).length > 0, 'the init message');
  await deliver(page, `hex:${hex(HELLO)}`);

  const welcome = await waitFor(async () => {
    const values = binaries(await sent(page));

    return values.length > 0 ? values[0] : null;
  }, 'WELCOME');

  equal('WELCOME forwarded', welcome, hex(WELCOME));
  await waitFor(() => state.wsOpened === 1, 'the websocket');

  const states = controls(await sent(page)).filter((v) => v.t === 'status').map((v) => v.state);
  check('reached connected', states.includes('connected'), JSON.stringify(states));
});

// The one downlink rule the injected boundary imposes: one complete frame per
// message, however the relay chose to batch them.
scenario('a downlink batch is split into one frame per message', async (browser) => {
  const { page, state } = await newPage(browser);
  await page.goto(bridgeURL());
  await waitFor(async () => (await sent(page)).length > 0, 'the init message');
  await deliver(page, `hex:${hex(HELLO)}`);
  await waitFor(() => state.wsOpened === 1, 'the websocket');

  const first = frame(TYPE_DATA, 17, new Uint8Array([1, 2, 3]));
  const second = frame(TYPE_DATA, 17, new Uint8Array([4, 5]));
  const third = frame(TYPE_DATA, 33, new Uint8Array(600).fill(7));

  state.socket.send(Buffer.from(bytes(first, second, third)));

  const delivered = await waitFor(async () => {
    const values = binaries(await sent(page));

    return values.length >= 4 ? values : null;
  }, 'three data frames');

  equal('frame 1', delivered[1], hex(first));
  equal('frame 2', delivered[2], hex(second));
  equal('frame 3', delivered[3], hex(third));
  equal('nothing merged', delivered.length, 4);
});

// Uplink is forwarded whole and unexamined -- the bridge never interprets DATA.
scenario('uplink frames reach the socket unchanged', async (browser) => {
  const { page, state } = await newPage(browser);
  await page.goto(bridgeURL());
  await waitFor(async () => (await sent(page)).length > 0, 'the init message');
  await deliver(page, `hex:${hex(HELLO)}`);
  await waitFor(() => state.wsOpened === 1, 'the websocket');

  const open = frame(0x01, 17);
  const data = frame(TYPE_DATA, 17, new Uint8Array([9, 9, 9]));

  await deliver(page, `hex:${hex(open)}`);
  await deliver(page, `hex:${hex(data)}`);

  const messages = await waitFor(() => (state.wsMessages.length >= 2 ? state.wsMessages : null), 'two uplink messages');
  equal('OPEN forwarded', messages[0], hex(open));
  equal('DATA forwarded', messages[1], hex(data));
});

// The websocket carrier does not resume. Losing it is terminal, and the client
// learns that from {t:'close'} -- which is what starts its own retry ladder.
scenario('losing the socket reports failed then close', async (browser) => {
  const { page, state } = await newPage(browser);
  await page.goto(bridgeURL());
  await waitFor(async () => (await sent(page)).length > 0, 'the init message');
  await deliver(page, `hex:${hex(HELLO)}`);
  await waitFor(() => state.wsOpened === 1, 'the websocket');

  state.socket.close({ code: 1006 });

  const values = await waitFor(async () => {
    const seen = controls(await sent(page));

    return seen.some((v) => v.t === 'close') ? seen : null;
  }, 'the close control');

  const order = values.map((v) => (v.t === 'status' ? `status:${v.state}` : v.t));
  check('failed precedes close', order.indexOf('status:failed') < order.indexOf('close'), JSON.stringify(order));
});

// The client sends this when the user replaces or disables the proxy. Ignoring
// it orphans a relay session until the idle grace reclaims it.
scenario('a close from the client releases the session', async (browser) => {
  const { page, state } = await newPage(browser);
  await page.goto(bridgeURL());
  await waitFor(async () => (await sent(page)).length > 0, 'the init message');
  await deliver(page, `hex:${hex(HELLO)}`);
  await waitFor(() => state.wsOpened === 1, 'the websocket');

  await deliver(page, JSON.stringify({ t: 'close' }));
  await waitFor(() => state.deletes > 0, 'the DELETE');

  equal('session deleted once', state.deletes, 1);
});

// The Desktop boundary does not publish whether control values arrive as JSON
// text or as parsed objects, so the bridge accepts both. This pins the object
// form, which the string-only reading would drop on the floor.
scenario('a control value is accepted as a parsed object too', async (browser) => {
  const { page, state } = await newPage(browser);
  await page.goto(bridgeURL());
  await waitFor(async () => (await sent(page)).length > 0, 'the init message');
  await deliver(page, `hex:${hex(HELLO)}`);
  await waitFor(() => state.wsOpened === 1, 'the websocket');

  await deliver(page, { t: 'close' });
  await waitFor(() => state.deletes > 0, 'the DELETE');

  equal('session deleted once', state.deletes, 1);
});

// A malformed downlink cannot be forwarded to the app: the boundary contract is
// one COMPLETE frame per message, so a truncated batch is terminal, not partial.
scenario('a truncated downlink batch is terminal', async (browser) => {
  const { page, state } = await newPage(browser);
  await page.goto(bridgeURL());
  await waitFor(async () => (await sent(page)).length > 0, 'the init message');
  await deliver(page, `hex:${hex(HELLO)}`);
  await waitFor(() => state.wsOpened === 1, 'the websocket');

  state.socket.send(Buffer.from(bytes(frame(TYPE_DATA, 17, new Uint8Array([1, 2, 3]))).slice(0, 6)));

  const values = await waitFor(async () => {
    const seen = controls(await sent(page));

    return seen.some((v) => v.t === 'close') ? seen : null;
  }, 'the close control');

  check('no frame delivered', binaries(await sent(page)).length === 1, 'only WELCOME should have been delivered');
  check('closed', values.some((v) => v.t === 'close'));
});

// The whole point of the exercise: the page must survive the client's policy.
// Any violation at all is a page that silently does nothing on that platform.
scenario('no CSP violations across a full session', async (browser) => {
  const { page, state } = await newPage(browser);
  await page.goto(bridgeURL());
  await waitFor(async () => (await sent(page)).length > 0, 'the init message');
  await deliver(page, `hex:${hex(HELLO)}`);
  await waitFor(() => state.wsOpened === 1, 'the websocket');

  state.socket.send(Buffer.from(frame(TYPE_DATA, 17, new Uint8Array([1]))));
  await page.waitForTimeout(200);

  const seen = await violations(page);
  check('zero violations', seen.length === 0, JSON.stringify(seen));

  const errors = await page.evaluate('window.__pageErrors || []');
  check('no page errors', errors.length === 0, JSON.stringify(errors));
});

// ------------------------------------------------------------------- runner

// Exit 2 means "this environment cannot run the harness" -- no browser binary,
// or one Playwright will not drive. The Go test skips on 2 and fails on 1, so a
// missing download never masquerades as a passing bridge page, and never
// masquerades as a broken one either.
let browser;

try {
  browser = await chromium.launch({
    executablePath: process.env.MTG_BROWSER_EXECUTABLE || undefined,
  });
} catch (err) {
  console.log(`harness cannot start a browser: ${err.message}`);
  process.exit(2);
}

for (const { name, fn } of scenarios) {
  console.log(`- ${name}`);

  try {
    await fn(browser);
  } catch (err) {
    failures += 1;
    console.log(`  FAIL ${name} -- ${err.message}`);
  }
}

await browser.close();

console.log(`\n${checks} checks, ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
