// The bridge: the JavaScript half of the WEB proxy v1 carrier.
//
// It runs inside the Telegram client's own WebView, under a Content-Security-
// Policy the client injects at document start and which this file cannot see or
// relax. It moves opaque frames between the client and the relay and does
// nothing else -- it never interprets DATA, never builds an MTProto payload and
// never assigns a stream id.
//
// Written to ES5 syntax on purpose. The runtime APIs it uses (fetch, Promise,
// WebSocket, MessageChannel, AbortController, typed arrays) are all permitted by
// the injected policy; the syntax level is what keeps it parseable in the oldest
// WebView any supported client embeds.
//
// Everything here has to survive an environment where storage, workers,
// BroadcastChannel, window.open, cookies and the dialog functions are shimmed
// away or inert. It therefore keeps no state anywhere but in this closure.
(function () {
  'use strict';

  // TPROXY_BOOT is written by the page generator immediately above this
  // function: {host, token, mode}. The token appears in that one response and
  // nowhere else.
  var BOOT = TPROXY_BOOT;

  var ORIGIN = 'https://' + BOOT.host;
  var SESSION_URL = ORIGIN + '/api/v1/session';
  var WS_URL = 'wss://' + BOOT.host + '/api/v1/ws';

  // Wire bounds. Every one of these is compiled into the client too and is
  // never negotiated, so they are constants rather than configuration.
  var HEADER_SIZE = 8;
  var MAX_PAYLOAD = 1048576;
  var MAX_BATCH = 2097152;
  var MAX_FRAMES = 4096;

  // The bridge's own memory bound, independent of the per-stream window: queued
  // plus browser-buffered uplink. An in-flight send counts until the socket
  // reports it drained, so a slow upload cannot hide a batch from this limit.
  var MAX_QUEUED_BYTES = 33554432;
  var MAX_QUEUED_ITEMS = 16384;

  // Session creation is the only HTTP request this carrier makes, and the only
  // place a retry is meaningful. A fixed attempt count never applies; a budget
  // does.
  var RETRY_BUDGET_MS = 90000;
  var RETRY_BASE_MS = 250;
  var RETRY_MAX_MS = 5000;

  var TRAFFIC_INTERVAL_MS = 2000;

  // ---------------------------------------------------------------- utilities

  function asBytes(value) {
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }

    if (value && value.buffer instanceof ArrayBuffer && typeof value.byteLength === 'number') {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }

    return null;
  }

  // copyOut returns a standalone ArrayBuffer. Never hand out a view onto a
  // larger buffer: a native bridge may serialise the whole underlying buffer,
  // which would leak the rest of the batch into a message that must carry one
  // frame.
  function copyOut(bytes) {
    var copy = new Uint8Array(bytes.length);
    copy.set(bytes);

    return copy.buffer;
  }

  // splitFrames cuts a batch at frame boundaries, returning null for anything
  // that is not a whole number of well-formed frames. It reads the declared
  // length with a multiply rather than a shift, because a 32-bit left shift in
  // JavaScript is signed and a payload length above 2^31 would come back
  // negative and walk the offset backwards -- an infinite loop on attacker
  // input.
  function splitFrames(bytes) {
    var frames = [];
    var offset = 0;

    while (offset < bytes.length) {
      if (bytes.length - offset < HEADER_SIZE) {
        return null;
      }

      var length = (bytes[offset + 4] * 16777216) +
        (bytes[offset + 5] * 65536) +
        (bytes[offset + 6] * 256) +
        bytes[offset + 7];

      if (length > MAX_PAYLOAD) {
        return null;
      }

      if (bytes.length - offset - HEADER_SIZE < length) {
        return null;
      }

      if (frames.length >= MAX_FRAMES) {
        return null;
      }

      frames.push(bytes.subarray(offset, offset + HEADER_SIZE + length));
      offset += HEADER_SIZE + length;
    }

    return frames;
  }

  function backoff(attempt) {
    var base = Math.min(RETRY_BASE_MS * Math.pow(2, attempt), RETRY_MAX_MS);

    return base / 2 + Math.random() * (base / 2);
  }

  // ---------------------------------------------------------------- boundaries
  //
  // Two client boundaries, one internal contract. The difference that matters
  // is downlink granularity: the injected WebView is fed ONE COMPLETE FRAME per
  // message, the loopback parent whole carrier batches.

  var boundary = null;

  function webviewBoundary(host, nonce) {
    return {
      framed: true,
      start: function () {
        // A plain property assignment, not addEventListener: the injected
        // object publishes onmessage as a callback slot and is not an
        // EventTarget.
        host.onmessage = function (value) {
          onClientValue(value);
        };

        // The nonce came from the fragment, which the client put there and
        // never sent to the server. The app accepts this message only when it
        // matches the WebView it opened.
        host.postMessage(JSON.stringify({
          t: 'tproxy-android-init',
          v: 1,
          nonce: nonce
        }));
      },
      sendControl: function (value) {
        // JSON text, which is the one form a reference client boundary is
        // documented to accept. Receipt is tolerant of both.
        host.postMessage(JSON.stringify(value));
      },
      sendBinary: function (buffer) {
        host.postMessage(buffer);
      }
    };
  }

  function loopbackBoundary(port) {
    return {
      framed: false,
      start: function () {
        port.onmessage = function (event) {
          onClientValue(event.data);
        };

        if (typeof port.start === 'function') {
          port.start();
        }
      },
      sendControl: function (value) {
        port.postMessage(value);
      },
      sendBinary: function (buffer) {
        port.postMessage(buffer);
      }
    };
  }

  // ------------------------------------------------------------- carrier state

  var socket = null;
  var sessionToken = null;
  var helloBytes = null;
  var uplinkQueue = [];
  var queuedBytes = 0;
  var upBytes = 0;
  var downBytes = 0;
  var trafficTimer = null;
  var state = '';
  var finished = false;

  function setState(next) {
    if (state === next || finished) {
      return;
    }

    state = next;

    if (boundary) {
      boundary.sendControl({ t: 'status', state: next });
    }
  }

  // fail is terminal. The websocket carrier does not resume a partially
  // delivered session: every stream dies with it and the client re-derives its
  // capability and asks for a fresh bridge page.
  function fail() {
    if (finished) {
      return;
    }

    setState('failed');
    finished = true;

    if (boundary) {
      boundary.sendControl({ t: 'close' });
    }

    stopTraffic();
    closeSocket();
    releaseSession();
  }

  function closeSocket() {
    if (!socket) {
      return;
    }

    var dying = socket;
    socket = null;
    dying.onopen = null;
    dying.onmessage = null;
    dying.onerror = null;
    dying.onclose = null;

    try {
      dying.close();
    } catch (err) {
      // A socket that refuses to close is already gone.
    }
  }

  // releaseSession is best effort by construction: the page may be unloading,
  // and if the request never leaves, the relay's idle grace reclaims the
  // session anyway.
  function releaseSession() {
    if (!sessionToken) {
      return;
    }

    var token = sessionToken;
    sessionToken = null;

    try {
      fetch(SESSION_URL, {
        method: 'DELETE',
        mode: 'same-origin',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        keepalive: true,
        headers: { Authorization: 'Bearer ' + token }
      })['catch'](function () {});
    } catch (err) {
      // Some engines refuse keepalive during unload. Nothing to do.
    }
  }

  function startTraffic() {
    if (boundary.framed || trafficTimer !== null) {
      return;
    }

    trafficTimer = setInterval(function () {
      boundary.sendControl({ t: 'traffic', up: upBytes, down: downBytes });
    }, TRAFFIC_INTERVAL_MS);
  }

  function stopTraffic() {
    if (trafficTimer !== null) {
      clearInterval(trafficTimer);
      trafficTimer = null;
    }
  }

  // ------------------------------------------------------------------- uplink

  function bufferedUplink() {
    return queuedBytes + (socket ? socket.bufferedAmount : 0);
  }

  function enqueueUplink(bytes) {
    if (bytes.length > MAX_BATCH) {
      fail();

      return;
    }

    if (uplinkQueue.length >= MAX_QUEUED_ITEMS || bufferedUplink() + bytes.length > MAX_QUEUED_BYTES) {
      fail();

      return;
    }

    if (socket && socket.readyState === 1) {
      upBytes += bytes.length;
      socket.send(copyOut(bytes));

      return;
    }

    uplinkQueue.push(bytes);
    queuedBytes += bytes.length;
  }

  function flushUplink() {
    var pending = uplinkQueue;
    uplinkQueue = [];
    queuedBytes = 0;

    for (var i = 0; i < pending.length; i++) {
      upBytes += pending[i].length;
      socket.send(copyOut(pending[i]));
    }
  }

  // ----------------------------------------------------------------- downlink

  function deliverDownlink(bytes) {
    downBytes += bytes.length;

    if (!boundary.framed) {
      boundary.sendBinary(copyOut(bytes));

      return;
    }

    var frames = splitFrames(bytes);

    if (frames === null) {
      fail();

      return;
    }

    for (var i = 0; i < frames.length; i++) {
      boundary.sendBinary(copyOut(frames[i]));
    }
  }

  // --------------------------------------------------------- client -> bridge

  function onClientValue(value) {
    if (finished) {
      return;
    }

    var bytes = asBytes(value);

    if (bytes !== null) {
      onClientBinary(bytes);

      return;
    }

    var control = value;

    if (typeof control === 'string') {
      try {
        control = JSON.parse(control);
      } catch (err) {
        return;
      }
    }

    // The client tells the bridge to go away when the user replaces or disables
    // the proxy. Honouring it is what stops an orphaned relay session.
    if (control && control.t === 'close') {
      finished = true;
      stopTraffic();
      closeSocket();
      releaseSession();
    }
  }

  function onClientBinary(bytes) {
    if (helloBytes === null) {
      // The first upstream binary message is the app's HELLO. The bridge does
      // not build it, inspect it or reformat it: it becomes the session
      // creation body verbatim, and a byte-identical retry depends on that.
      helloBytes = bytes;
      openSession();

      return;
    }

    enqueueUplink(bytes);
  }

  // ------------------------------------------------------------ session setup

  function openSession() {
    setState('connecting');

    var body = copyOut(helloBytes);
    var deadline = Date.now() + RETRY_BUDGET_MS;

    attemptSession(body, deadline, 0);
  }

  function attemptSession(body, deadline, attempt) {
    if (finished) {
      return;
    }

    fetch(SESSION_URL, {
      method: 'POST',
      mode: 'same-origin',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      headers: {
        Authorization: 'Bearer ' + BOOT.token,
        'Content-Type': 'application/octet-stream'
      },
      body: body
    }).then(function (response) {
      if (response.status === 200) {
        return response.arrayBuffer().then(function (welcome) {
          onSession(response.headers.get('X-Session-Token'), welcome);
        });
      }

      // 503 is the relay saying "authenticated, but not now": the bootstrap is
      // unconsumed and the identical request is safe to repeat. Every other
      // status is terminal -- retrying a 404 only tells a prober how long we
      // keep trying.
      if (response.status === 503) {
        return retrySession(body, deadline, attempt);
      }

      fail();

      return null;
    })['catch'](function () {
      // A transport failure is ambiguous: the request may or may not have been
      // applied. Session creation is idempotent on the bootstrap precisely so
      // this retry is safe.
      retrySession(body, deadline, attempt);
    });
  }

  function retrySession(body, deadline, attempt) {
    if (finished) {
      return null;
    }

    var wait = backoff(attempt);

    if (Date.now() + wait > deadline) {
      fail();

      return null;
    }

    setState('reconnecting');
    setTimeout(function () {
      attemptSession(body, deadline, attempt + 1);
    }, wait);

    return null;
  }

  function onSession(token, welcome) {
    if (finished) {
      return;
    }

    if (!token) {
      fail();

      return;
    }

    sessionToken = token;

    // WELCOME reaches the app before the socket exists. That is the required
    // order: the client may create streams only after it sees WELCOME, and
    // anything it sends before the socket opens waits in the uplink queue.
    boundary.sendBinary(welcome);

    openSocket();
  }

  function openSocket() {
    try {
      socket = new WebSocket(WS_URL, 'tproxy-v1.' + sessionToken);
    } catch (err) {
      fail();

      return;
    }

    socket.binaryType = 'arraybuffer';

    socket.onopen = function () {
      setState('connected');
      startTraffic();
      flushUplink();
    };

    socket.onmessage = function (event) {
      if (finished) {
        return;
      }

      // The relay never sends text. One that appears is either a middlebox or a
      // bug, and in both cases the frame stream can no longer be trusted.
      var bytes = asBytes(event.data);

      if (bytes === null || bytes.length > MAX_BATCH) {
        fail();

        return;
      }

      if (bytes.length === 0) {
        return;
      }

      deliverDownlink(bytes);
    };

    socket.onerror = function () {
      fail();
    };

    socket.onclose = function () {
      fail();
    };
  }

  // ------------------------------------------------------------------- attach

  function attach(next) {
    if (boundary || finished) {
      return;
    }

    boundary = next;
    boundary.start();
    setState('connecting');
  }

  function attachLoopbackParent(event) {
    // Accepted once, only from the parent window, only with that exact shape,
    // only one transferred port, and only from an explicit loopback origin.
    // This is the client's own system-browser fallback and nothing else may
    // reach it.
    if (boundary || event.source !== window.parent || window.parent === window) {
      return;
    }

    if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(event.origin)) {
      return;
    }

    var data = event.data;

    if (!data || data.t !== 'tproxy-init' || data.v !== 1) {
      return;
    }

    if (!event.ports || event.ports.length !== 1) {
      return;
    }

    attach(loopbackBoundary(event.ports[0]));
  }

  function start() {
    // The fragment carries the WebView nonce and is read before the query and
    // fragment are replaced away. It never reached the server.
    var hash = window.location.hash || '';
    var match = /^#android=([A-Za-z0-9_-]{43})$/.exec(hash);
    var nonce = match ? match[1] : null;

    try {
      window.history.replaceState(null, '', '/');
    } catch (err) {
      // A client that forbids history manipulation still works; the URL simply
      // stays visible in a place no user can see.
    }

    window.addEventListener('message', attachLoopbackParent);

    var host = window.TelegramWebProxy;

    if (host && typeof host.postMessage === 'function' && nonce) {
      attach(webviewBoundary(host, nonce));
    }

    // Best-effort teardown. pagehide covers the back-forward cache; unload is
    // the older engines.
    window.addEventListener('pagehide', releaseSession);
    window.addEventListener('unload', releaseSession);
  }

  start();
})();
