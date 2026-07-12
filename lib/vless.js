// lib/vless.js
// Minimal VLESS client: parses a vless:// share link, opens a TCP+TLS(+WS)
// connection to a *candidate* Cloudflare IP while keeping the original
// domain in the TLS SNI and WebSocket Host header (this is the mechanism
// that lets a different edge IP still route to your own backend), sends
// a real VLESS request header, and measures TTFB + throughput of the
// response.
//
// VLESS is a light, unencrypted-at-the-app-layer protocol (it relies on
// the outer TLS for confidentiality), which makes it realistic to
// implement directly here. VMess adds AEAD encryption / timestamp-based
// auth on top and is not implemented yet -- see README.

const net = require("net");
const tls = require("tls");
const crypto = require("crypto");

// ---- share-link parsing -----------------------------------------------

function parseVlessLink(link) {
  const url = new URL(link);
  if (url.protocol !== "vless:") {
    throw new Error("Not a vless:// link");
  }
  const uuid = decodeURIComponent(url.username);
  const address = url.hostname;
  const port = parseInt(url.port, 10) || 443;
  const params = Object.fromEntries(url.searchParams.entries());
  return {
    uuid,
    address, // original domain the config points at
    port,
    security: params.security || "none", // "tls" expected for CF fronting
    network: params.type || "tcp", // "ws" expected for CF fronting
    sni: params.sni || params.host || address,
    wsPath: params.path ? decodeURIComponent(params.path) : "/",
    wsHost: params.host || address,
    fp: params.fp || "chrome",
  };
}

// ---- VLESS request header ----------------------------------------------
// version(1) + uuid(16) + addon-len(1) + command(1) + port(2) + atyp(1) + addr

function uuidToBytes(uuid) {
  const hex = uuid.replace(/-/g, "");
  return Buffer.from(hex, "hex");
}

function buildVlessHeader(uuid, destHost, destPort) {
  const parts = [];
  parts.push(Buffer.from([0x00])); // version
  parts.push(uuidToBytes(uuid));
  parts.push(Buffer.from([0x00])); // no addons
  parts.push(Buffer.from([0x01])); // command: TCP
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(destPort, 0);
  parts.push(portBuf);

  const isIp = net.isIP(destHost);
  if (isIp === 4) {
    parts.push(Buffer.from([0x01]));
    parts.push(Buffer.from(destHost.split(".").map(Number)));
  } else if (isIp === 6) {
    parts.push(Buffer.from([0x03]));
    parts.push(Buffer.from(destHost.replace(/:/g, "")));
  } else {
    parts.push(Buffer.from([0x02]));
    const hostBuf = Buffer.from(destHost, "utf8");
    parts.push(Buffer.from([hostBuf.length]));
    parts.push(hostBuf);
  }
  return Buffer.concat(parts);
}

// ---- fragment presets ---------------------------------------------------
// Splits the *first* TLS ClientHello write into several smaller TCP
// writes with small delays, to avoid naive DPI signature matching on
// the initial handshake. This is a best-effort, JS-level approximation
// of what dedicated fragment tools do at the OS/socket layer -- it will
// not be as robust against sophisticated middleboxes, but matches the
// same general technique exposed as "fragment" options in common
// proxy clients.

const FRAGMENT_PRESETS = {
  none: null,
  light: { chunks: 2, chunkBytes: 20, delayMs: 8 },
  medium: { chunks: 4, chunkBytes: 8, delayMs: 20 },
  heavy: { chunks: 8, chunkBytes: 2, delayMs: 45 },
};

function wrapSocketWithFragment(socket, preset) {
  if (!preset) return;
  const original = socket.write.bind(socket);
  let writesIntercepted = 0;
  const maxWritesToIntercept = 1; // only the ClientHello (first write)

  socket.write = function (data, ...rest) {
    if (writesIntercepted >= maxWritesToIntercept || !Buffer.isBuffer(data)) {
      return original(data, ...rest);
    }
    writesIntercepted++;
    (async () => {
      let offset = 0;
      let chunkIdx = 0;
      while (offset < data.length) {
        const size =
          chunkIdx < preset.chunks
            ? Math.min(preset.chunkBytes, data.length - offset)
            : data.length - offset;
        const slice = data.subarray(offset, offset + size);
        original(slice);
        offset += size;
        chunkIdx++;
        if (offset < data.length) {
          await new Promise((r) => setTimeout(r, preset.delayMs));
        }
      }
      socket.write = original; // restore normal behavior after ClientHello
    })();
    return true;
  };
}

// ---- minimal WebSocket client handshake ---------------------------------

function sendWsUpgrade(tlsSocket, { host, path }) {
  const key = crypto.randomBytes(16).toString("base64");
  const req =
    `GET ${path} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `Upgrade: websocket\r\n` +
    `Connection: Upgrade\r\n` +
    `Sec-WebSocket-Key: ${key}\r\n` +
    `Sec-WebSocket-Version: 13\r\n\r\n`;
  tlsSocket.write(req);
}

function wsFrame(payload) {
  // Minimal unmasked-from-client... actually clients MUST mask frames.
  const maskKey = crypto.randomBytes(4);
  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) {
    masked[i] = payload[i] ^ maskKey[i % 4];
  }
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x82, 0x80 | payload.length]);
  } else {
    header = Buffer.alloc(4);
    header[0] = 0x82;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
  }
  return Buffer.concat([header, maskKey, masked]);
}

// Stateful WS frame reader: server->client frames (and their payloads) can
// arrive split across many TCP/TLS reads once payloads get past a few
// hundred bytes -- a naive "unwrap whatever chunk just arrived" approach
// (the previous version of this file) mis-parses continuation bytes as
// fresh frame headers and silently corrupts the byte count. This version
// buffers across calls and only ever emits complete frame payloads.
function createWsFrameReader(onPayload) {
  let buf = Buffer.alloc(0);

  function push(chunk) {
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    while (true) {
      if (buf.length < 2) return;
      const opcode = buf[0] & 0x0f;
      const byte1 = buf[1];
      const masked = (byte1 & 0x80) !== 0;
      let len = byte1 & 0x7f;
      let offset = 2;

      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        offset = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        const high = buf.readUInt32BE(2);
        const low = buf.readUInt32BE(6);
        if (high !== 0) return; // absurdly large frame; not expected here
        len = low;
        offset = 10;
      }

      let maskKey = null;
      if (masked) {
        if (buf.length < offset + 4) return;
        maskKey = buf.subarray(offset, offset + 4);
        offset += 4;
      }

      if (buf.length < offset + len) return; // wait for the rest of this frame

      let payload = buf.subarray(offset, offset + len);
      if (masked) {
        const unmasked = Buffer.alloc(len);
        for (let i = 0; i < len; i++) unmasked[i] = payload[i] ^ maskKey[i % 4];
        payload = unmasked;
      }

      if (opcode === 0x1 || opcode === 0x2 || opcode === 0x0) {
        onPayload(payload);
      }
      // opcodes 0x8/0x9/0xA (close/ping/pong) are skipped -- fine for a
      // short-lived one-shot test that doesn't need to keep a long-lived
      // connection alive.

      buf = buf.subarray(offset + len);
    }
  }

  return { push };
}

function extractExpectedBytes(path) {
  const m = /bytes=(\d+)/.exec(path || "");
  return m ? parseInt(m[1], 10) : null;
}

// ---- end-to-end proxy test ----------------------------------------------
//
// Connects to `candidateIp:candidatePort`, TLS+WS to the original domain,
// sends a VLESS request pointing at `testTarget`, and measures TTFB /
// throughput of the response the remote server relays back.
//
// "Success" requires all of:
//   1. WS upgrade accepted (101)
//   2. VLESS response header parsed and the *inner* HTTP response headers
//      (from the relayed request to testTarget) parsed with a 2xx status
//   3. At least half of the requested test bytes actually arrived
// Getting only the 2-byte VLESS ack (which arrives regardless of whether
// the downstream fetch ever succeeds) is explicitly NOT enough -- that
// was the bug in the previous version of this function, which reported
// "verified" for essentially any reachable, correctly-SNI-routed edge
// even when the real test request never completed.

function testVlessConnection({
  candidateIp,
  candidatePort,
  config,
  fragmentPreset = "none",
  testTarget = { host: "speed.cloudflare.com", port: 80, path: "/__down?bytes=131072" },
  timeoutMs = 8000,
}) {
  const expectedBytes = extractExpectedBytes(testTarget.path);
  const minSuccessBytes = expectedBytes ? Math.floor(expectedBytes * 0.5) : 4096;

  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    let resolved = false;

    // -- inner-HTTP-response parsing state (after stripping VLESS header) --
    let sawFirstRespByte = false;
    let ttfbMs = null;
    let headerParsed = false;
    let headerBuf = Buffer.alloc(0);
    let statusCode = null;
    let bodyBytes = 0;

    function handleHttpChunk(chunk) {
      if (!sawFirstRespByte) {
        sawFirstRespByte = true;
        ttfbMs = Number(process.hrtime.bigint() - start) / 1e6;
      }
      if (!headerParsed) {
        headerBuf = Buffer.concat([headerBuf, chunk]);
        const idx = headerBuf.indexOf("\r\n\r\n");
        if (idx === -1) return; // still waiting for full inner-HTTP headers
        const statusLine = headerBuf.subarray(0, idx).toString().split("\r\n")[0];
        statusCode = parseInt(statusLine.split(" ")[1], 10) || null;
        headerParsed = true;
        bodyBytes += headerBuf.length - (idx + 4);
        return;
      }
      bodyBytes += chunk.length;
    }

    // -- VLESS response header (version + addon-len + addons) stripping --
    let vlessHeaderBuf = Buffer.alloc(0);
    let vlessHeaderDone = false;
    let vlessHeaderNeeded = null;

    function handleVlessStreamChunk(chunk) {
      if (!vlessHeaderDone) {
        vlessHeaderBuf = Buffer.concat([vlessHeaderBuf, chunk]);
        if (vlessHeaderNeeded === null && vlessHeaderBuf.length >= 2) {
          vlessHeaderNeeded = 2 + vlessHeaderBuf[1]; // version(1) + addonLen(1) + addons
        }
        if (vlessHeaderNeeded === null || vlessHeaderBuf.length < vlessHeaderNeeded) return;
        vlessHeaderDone = true;
        const remainder = vlessHeaderBuf.subarray(vlessHeaderNeeded);
        if (remainder.length > 0) handleHttpChunk(remainder);
        return;
      }
      handleHttpChunk(chunk);
    }

    const wsReader = createWsFrameReader(handleVlessStreamChunk);

    const done = (result) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(hardTimeout);
      try {
        rawSocket.destroy();
      } catch (_) {}
      resolve(result);
    };

    const hardTimeout = setTimeout(() => {
      done({
        success: false,
        error: headerParsed
          ? `timeout -- only ${bodyBytes} of ~${expectedBytes ?? "?"} bytes received`
          : sawFirstRespByte
          ? "timeout -- response headers never completed"
          : "timeout -- no response after VLESS handshake",
        httpStatus: statusCode,
        bytesReceived: bodyBytes,
      });
    }, timeoutMs);

    const rawSocket = net.connect({ host: candidateIp, port: candidatePort });

    rawSocket.on("error", (err) => done({ success: false, error: err.message }));

    rawSocket.on("connect", () => {
      const preset = FRAGMENT_PRESETS[fragmentPreset] || null;
      wrapSocketWithFragment(rawSocket, preset);

      const tlsSocket = tls.connect({
        socket: rawSocket,
        servername: config.sni,
        rejectUnauthorized: true,
      });

      tlsSocket.on("error", (err) => done({ success: false, error: `tls: ${err.message}` }));

      let phase = "ws-handshake";
      let httpBuf = Buffer.alloc(0);

      tlsSocket.on("secureConnect", () => {
        sendWsUpgrade(tlsSocket, { host: config.wsHost, path: config.wsPath });
      });

      tlsSocket.on("data", (chunk) => {
        if (phase === "ws-handshake") {
          httpBuf = Buffer.concat([httpBuf, chunk]);
          const headerEnd = httpBuf.indexOf("\r\n\r\n");
          if (headerEnd === -1) return;
          const statusLine = httpBuf.subarray(0, 20).toString();
          if (!statusLine.includes("101")) {
            return done({ success: false, error: `ws upgrade rejected: ${statusLine.trim()}` });
          }
          phase = "vless-response";
          const header = buildVlessHeader(config.uuid, testTarget.host, testTarget.port);
          const payload = Buffer.from(
            `GET ${testTarget.path} HTTP/1.1\r\nHost: ${testTarget.host}\r\nConnection: close\r\n\r\n`
          );
          tlsSocket.write(wsFrame(Buffer.concat([header, payload])));

          const leftover = httpBuf.subarray(headerEnd + 4);
          if (leftover.length > 0) wsReader.push(leftover);
          return;
        }

        wsReader.push(chunk);
      });

      tlsSocket.on("close", () => {
        if (resolved) return;

        if (!headerParsed) {
          return done({
            success: false,
            error: sawFirstRespByte
              ? "connection closed before inner-HTTP response headers completed"
              : "connection closed with no response data after VLESS handshake (handshake alone isn't proof the tunnel works)",
          });
        }
        if (statusCode == null || statusCode >= 400) {
          return done({
            success: false,
            error: `upstream test request returned status ${statusCode ?? "unknown"}`,
            httpStatus: statusCode,
            bytesReceived: bodyBytes,
          });
        }
        if (bodyBytes < minSuccessBytes) {
          return done({
            success: false,
            error: `only ${bodyBytes} of ~${expectedBytes ?? minSuccessBytes} bytes received before close -- edge likely congested or throttled`,
            httpStatus: statusCode,
            bytesReceived: bodyBytes,
          });
        }

        const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
        const throughputMbps = (bodyBytes * 8) / 1000 / Math.max(elapsedMs, 1);
        done({
          success: true,
          ttfbMs: Math.round(ttfbMs * 10) / 10,
          throughputMbps: Math.round(throughputMbps * 100) / 100,
          bytesReceived: bodyBytes,
          httpStatus: statusCode,
        });
      });
    });
  });
}

module.exports = {
  parseVlessLink,
  buildVlessHeader,
  testVlessConnection,
  FRAGMENT_PRESETS,
};
