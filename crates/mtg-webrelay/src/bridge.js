// The bridge: the JavaScript half of the WEB proxy v1 multi-carrier transport.
//
// Runs inside the Telegram client's own WebView (Android/iOS/Desktop) or
// loopback iframe fallback under a strict intersected Content-Security-Policy.
// Supports all 4 carriers (`websocket`, `ws-lanes`, `https`, `https-lanes`)
// plus `auto` self-healing failover from WebSocket to HTTPS Conveyor!
// Written strictly in ES5 syntax with zero forbidden WebView APIs.
(function () {
  'use strict';

  var BOOT = TPROXY_BOOT;

  var BASE_PATH = BOOT.base || '/api/v1';
  var ORIGIN = 'https://' + BOOT.host;
  var SESSION_URL = ORIGIN + BASE_PATH + '/session';
  var WS_URL = 'wss://' + BOOT.host + BASE_PATH + '/ws';
  var UP_URL = ORIGIN + BASE_PATH + '/up';
  var DOWN_URL = ORIGIN + BASE_PATH + '/down';

  var HEADER_SIZE = 8;
  var MAX_PAYLOAD = 1048576;
  var MAX_BATCH = 2097152;
  var MAX_FRAMES = 4096;

  var MAX_QUEUED_BYTES = 33554432;
  var MAX_QUEUED_ITEMS = 16384;

  var RETRY_BUDGET_MS = 90000;
  var RETRY_BASE_MS = 250;
  var RETRY_MAX_MS = 5000;

  var TRAFFIC_INTERVAL_MS = 2000;

  function asBytes(value) {
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }

    if (value && value.buffer instanceof ArrayBuffer && typeof value.byteLength === 'number') {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }

    return null;
  }

  function copyOut(bytes) {
    var copy = new Uint8Array(bytes.length);
    copy.set(bytes);

    return copy.buffer;
  }

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

  var boundary = null;
  var deliveryChannel = null;

  function deliverFrom(channel, value) {
    if (deliveryChannel === null) {
      deliveryChannel = channel;
    }

    if (deliveryChannel !== channel) {
      return;
    }

    onClientValue(unwrapMessage(value));
  }

  function unwrapMessage(value) {
    if (!value || typeof value !== 'object') {
      return value;
    }

    try {
      if (window.Event && value instanceof window.Event) {
        return value.data;
      }
    } catch (err) {
      // Engine without global Event or hostile getter.
    }

    if (value.t !== undefined) {
      return value;
    }

    var inner = value.data;

    if (inner === undefined || inner === null) {
      return value;
    }

    if (typeof inner === 'string' || asBytes(inner) !== null) {
      return inner;
    }

    return value;
  }

  function webviewBoundary(host, nonce) {
    return {
      framed: true,
      start: function () {
        host.onmessage = function (value) {
          deliverFrom('slot', value);
        };

        if (typeof host.addEventListener === 'function') {
          host.addEventListener('message', function (event) {
            deliverFrom('listener', event);
          });
        }

        host.postMessage(JSON.stringify({
          t: 'tproxy-android-init',
          v: 1,
          nonce: nonce
        }));
      },
      sendControl: function (value) {
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

  var socket = null;
  var laneSockets = [];
  var laneCursor = 0;
  var activeMode = 'websocket';
  var activeLanes = 1;
  var wsEverOpened = false;
  var httpsActive = false;
  var upSeq = 0;
  var upInFlight = 0;
  var maxUpInFlight = 1;
  var downCursor = '0';
  var downFailures = 0;
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

  function fail() {
    if (finished) {
      return;
    }

    setState('failed');
    finished = true;
    httpsActive = false;

    if (boundary) {
      boundary.sendControl({ t: 'close' });
    }

    stopTraffic();
    closeAllSockets();
    releaseSession();
  }

  function closeOneSocket(dying) {
    if (!dying) {
      return;
    }

    dying.onopen = null;
    dying.onmessage = null;
    dying.onerror = null;
    dying.onclose = null;

    try {
      dying.close();
    } catch (err) {
      // Already closed.
    }
  }

  function closeAllSockets() {
    if (socket) {
      var primary = socket;
      socket = null;
      closeOneSocket(primary);
    }

    if (laneSockets.length > 0) {
      var list = laneSockets;
      laneSockets = [];
      for (var i = 0; i < list.length; i++) {
        closeOneSocket(list[i]);
      }
    }
  }

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
      // Engine refused keepalive during unload.
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

  function bufferedUplink() {
    var total = queuedBytes + (socket ? socket.bufferedAmount : 0);
    for (var i = 0; i < laneSockets.length; i++) {
      if (laneSockets[i]) {
        total += laneSockets[i].bufferedAmount;
      }
    }
    return total;
  }

  function pickOpenLane() {
    var count = laneSockets.length;
    for (var i = 0; i < count; i++) {
      var idx = (laneCursor + i) % count;
      var ws = laneSockets[idx];
      if (ws && ws.readyState === 1) {
        laneCursor = (idx + 1) % count;
        return ws;
      }
    }
    return null;
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

    if (httpsActive) {
      uplinkQueue.push(bytes);
      queuedBytes += bytes.length;
      pumpHttpsUplink();

      return;
    }

    if (activeMode === 'ws-lanes') {
      var lane = pickOpenLane();
      if (lane) {
        upBytes += bytes.length;
        lane.send(copyOut(bytes));

        return;
      }
    } else if (socket && socket.readyState === 1) {
      upBytes += bytes.length;
      socket.send(copyOut(bytes));

      return;
    }

    uplinkQueue.push(bytes);
    queuedBytes += bytes.length;
  }

  function flushUplink() {
    if (httpsActive) {
      pumpHttpsUplink();

      return;
    }

    var pending = uplinkQueue;
    uplinkQueue = [];
    queuedBytes = 0;

    for (var i = 0; i < pending.length; i++) {
      var target = activeMode === 'ws-lanes' ? pickOpenLane() : socket;
      if (!target || target.readyState !== 1) {
        uplinkQueue.push(pending[i]);
        queuedBytes += pending[i].length;
        continue;
      }
      upBytes += pending[i].length;
      target.send(copyOut(pending[i]));
    }
  }

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

    if (control && control.t === 'close') {
      finished = true;
      httpsActive = false;
      stopTraffic();
      closeAllSockets();
      releaseSession();
    }
  }

  function onClientBinary(bytes) {
    if (helloBytes === null) {
      helloBytes = bytes;
      openSession();

      return;
    }

    enqueueUplink(bytes);
  }

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

    var hdrs = {
      Authorization: 'Bearer ' + BOOT.token,
      'Content-Type': 'application/octet-stream'
    };
    if (BOOT.mode && BOOT.mode !== 'websocket') {
      hdrs['X-Carrier-Prefer'] = BOOT.mode;
    }

    fetch(SESSION_URL, {
      method: 'POST',
      mode: 'same-origin',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      headers: hdrs,
      body: body
    }).then(function (response) {
      if (response.status === 200) {
        return response.arrayBuffer().then(function (welcome) {
          var modeHdr = response.headers.get('X-Carrier-Mode') || 'websocket';
          var cursorHdr = response.headers.get('X-Down-Cursor') || '0';
          var lanesHdr = parseInt(response.headers.get('X-Carrier-Lanes') || '0', 10);
          onSession(response.headers.get('X-Session-Token'), welcome, modeHdr, cursorHdr, lanesHdr);
        });
      }

      if (response.status === 503) {
        return retrySession(body, deadline, attempt);
      }

      fail();

      return null;
    })['catch'](function () {
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

  function onSession(token, welcome, modeHdr, cursorHdr, lanesHdr) {
    if (finished) {
      return;
    }

    if (!token) {
      fail();

      return;
    }

    sessionToken = token;
    activeMode = modeHdr || 'websocket';
    downCursor = cursorHdr || '0';
    activeLanes = lanesHdr > 0 ? lanesHdr : (BOOT.lanes || 1);
    if (activeLanes > 8) {
      activeLanes = 8;
    }

    boundary.sendBinary(welcome);

    if (activeMode === 'https' || activeMode === 'https-lanes') {
      startHttpsCarrier(activeMode === 'https-lanes' ? Math.max(2, activeLanes) : 1);
    } else if (activeMode === 'ws-lanes') {
      openWsLanes(Math.max(2, activeLanes));
    } else {
      openSocket();
    }
  }

  // ---- HTTPS / HTTP/2 Conveyor Carrier (works on iOS WKWebView & WS-blocked nets) ----

  function startHttpsCarrier(lanes) {
    if (finished || httpsActive) {
      return;
    }

    closeAllSockets();
    httpsActive = true;
    maxUpInFlight = lanes;
    setState('connected');
    startTraffic();
    pumpHttpsUplink();
    pollHttpsDownlink();
  }

  function pumpHttpsUplink() {
    if (!httpsActive || finished || !sessionToken) {
      return;
    }

    while (upInFlight < maxUpInFlight && uplinkQueue.length > 0) {
      // Coalesce queued chunks up to MAX_BATCH per HTTP POST!
      var batchParts = [];
      var batchLen = 0;

      while (uplinkQueue.length > 0 && batchLen + uplinkQueue[0].length <= MAX_BATCH) {
        var nextChunk = uplinkQueue.shift();
        queuedBytes -= nextChunk.length;
        batchParts.push(nextChunk);
        batchLen += nextChunk.length;
      }

      if (batchParts.length === 0) {
        break;
      }

      var merged = new Uint8Array(batchLen);
      var off = 0;
      for (var i = 0; i < batchParts.length; i++) {
        merged.set(batchParts[i], off);
        off += batchParts[i].length;
      }

      var seq = upSeq;
      upSeq += 1;
      upInFlight += 1;
      upBytes += batchLen;
      sendHttpsUplink(merged.buffer, seq, 0);
    }
  }

  function sendHttpsUplink(buffer, seq, attempt) {
    if (!httpsActive || finished || !sessionToken) {
      upInFlight = Math.max(0, upInFlight - 1);
      return;
    }

    fetch(UP_URL, {
      method: 'POST',
      mode: 'same-origin',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      headers: {
        Authorization: 'Bearer ' + sessionToken,
        'Content-Type': 'application/octet-stream',
        'X-Up-Seq': String(seq)
      },
      body: buffer
    }).then(function (response) {
      if (response.status === 204 || response.status === 200) {
        upInFlight = Math.max(0, upInFlight - 1);
        pumpHttpsUplink();
        return;
      }
      if ((response.status === 503 || response.status >= 500) && attempt < 6) {
        setTimeout(function () {
          sendHttpsUplink(buffer, seq, attempt + 1);
        }, backoff(attempt));
        return;
      }
      fail();
    })['catch'](function () {
      if (!httpsActive || finished) {
        return;
      }
      if (attempt < 6) {
        setTimeout(function () {
          sendHttpsUplink(buffer, seq, attempt + 1);
        }, backoff(attempt));
        return;
      }
      fail();
    });
  }

  function pollHttpsDownlink() {
    if (!httpsActive || finished || !sessionToken) {
      return;
    }

    fetch(DOWN_URL + '?cursor=' + encodeURIComponent(downCursor), {
      method: 'GET',
      mode: 'same-origin',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      headers: {
        Authorization: 'Bearer ' + sessionToken
      }
    }).then(function (response) {
      if (!httpsActive || finished) {
        return null;
      }

      if (response.status === 204) {
        downFailures = 0;
        var keptCursor = response.headers.get('X-Down-Cursor');
        if (keptCursor) {
          downCursor = keptCursor;
        }
        pollHttpsDownlink();
        return null;
      }

      if (response.status === 200) {
        downFailures = 0;
        var nextCursor = response.headers.get('X-Down-Cursor');
        return response.arrayBuffer().then(function (buf) {
          if (!httpsActive || finished) {
            return;
          }
          if (nextCursor) {
            downCursor = nextCursor;
          }
          var bytes = asBytes(buf);
          if (bytes === null || bytes.length > MAX_BATCH) {
            fail();
            return;
          }
          if (bytes.length > 0) {
            deliverDownlink(bytes);
          }
          pollHttpsDownlink();
        });
      }

      if (response.status === 503 && downFailures < 6) {
        downFailures += 1;
        setTimeout(pollHttpsDownlink, backoff(downFailures));
        return null;
      }

      fail();
      return null;
    })['catch'](function () {
      if (!httpsActive || finished) {
        return;
      }
      if (downFailures < 6) {
        downFailures += 1;
        setTimeout(pollHttpsDownlink, backoff(downFailures));
        return;
      }
      fail();
    });
  }

  // ---- Classic Single WebSocket Carrier (with optional auto->https self-heal!) ----

  function handleWsFailure() {
    if (finished) {
      return;
    }
    if (!wsEverOpened && BOOT.fallback) {
      startHttpsCarrier(Math.max(1, activeLanes));
      return;
    }
    fail();
  }

  function openSocket() {
    try {
      socket = new WebSocket(WS_URL, 'tproxy-v1.' + sessionToken);
    } catch (err) {
      handleWsFailure();

      return;
    }

    socket.binaryType = 'arraybuffer';

    socket.onopen = function () {
      wsEverOpened = true;
      setState('connected');
      startTraffic();
      flushUplink();
    };

    socket.onmessage = function (event) {
      if (finished) {
        return;
      }

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
      handleWsFailure();
    };

    socket.onclose = function () {
      handleWsFailure();
    };
  }

  // ---- Multi-Lane Parallel WebSocket Carrier (`ws-lanes`) ----

  function openWsLanes(lanes) {
    laneSockets = [];
    for (var i = 0; i < lanes; i++) {
      openOneWsLane(i);
    }
  }

  function openOneWsLane(idx) {
    var ws;
    try {
      ws = new WebSocket(WS_URL + '?lane=' + idx, 'tproxy-v1.' + sessionToken);
    } catch (err) {
      handleWsFailure();
      return;
    }

    ws.binaryType = 'arraybuffer';
    laneSockets[idx] = ws;

    ws.onopen = function () {
      wsEverOpened = true;
      setState('connected');
      startTraffic();
      flushUplink();
    };

    ws.onmessage = function (event) {
      if (finished) {
        return;
      }
      var bytes = asBytes(event.data);
      if (bytes === null || bytes.length > MAX_BATCH) {
        fail();
        return;
      }
      if (bytes.length > 0) {
        deliverDownlink(bytes);
      }
    };

    ws.onerror = function () {
      laneSockets[idx] = null;
      if (!pickOpenLane()) {
        handleWsFailure();
      }
    };

    ws.onclose = function () {
      laneSockets[idx] = null;
      if (!pickOpenLane()) {
        handleWsFailure();
      }
    };
  }

  function attach(next) {
    if (boundary || finished) {
      return;
    }

    boundary = next;
    boundary.start();
    setState('connecting');
  }

  function attachLoopbackParent(event) {
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
    var hash = window.location.hash || '';
    var match = /^#android=([A-Za-z0-9_-]{43})$/.exec(hash);
    var nonce = match ? match[1] : null;

    try {
      window.history.replaceState(null, '', '/');
    } catch (err) {
      // History manipulation forbidden; continue.
    }

    window.addEventListener('message', attachLoopbackParent);

    var host = window.TelegramWebProxy;

    if (host && typeof host.postMessage === 'function' && nonce) {
      attach(webviewBoundary(host, nonce));
    }

    window.addEventListener('pagehide', releaseSession);
    window.addEventListener('unload', releaseSession);
  }

  start();
})();
