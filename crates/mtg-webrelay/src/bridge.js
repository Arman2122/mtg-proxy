// The bridge: the JavaScript half of the WEB proxy v1 carrier.
//
// Runs inside the Telegram client's own WebView (Android/iOS/Desktop) or
// loopback iframe fallback under a strict intersected Content-Security-Policy.
// Moves opaque Shared-Frame v1 batches between the client and the relay.
// Written strictly in ES5 syntax for maximum WebView compatibility.
(function () {
  'use strict';

  var BOOT = TPROXY_BOOT;

  var ORIGIN = 'https://' + BOOT.host;
  var SESSION_URL = ORIGIN + '/api/v1/session';
  var WS_URL = 'wss://' + BOOT.host + '/api/v1/ws';

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
      // Already closed.
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
      stopTraffic();
      closeSocket();
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

  function onSession(token, welcome) {
    if (finished) {
      return;
    }

    if (!token) {
      fail();

      return;
    }

    sessionToken = token;
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
