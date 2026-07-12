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

function unwrapWsFrame(buf) {
  // Best-effort single-frame unwrap of a server->client frame (unmasked).
  if (buf.length < 2) return null;
  const len1 = buf[1] & 0x7f;
  let offset = 2;
  let len = len1;
  if (len1 === 126) {
    len = buf.readUInt16BE(2);
    offset = 4;
  } else if (len1 === 127) {
    return null; // not needed for our small test payloads
  }
  return buf.subarray(offset, offset + len);
}

// ---- end-to-end proxy test ----------------------------------------------
//
// Connects to `candidateIp:candidatePort`, TLS+WS to the original domain,
// sends a VLESS request pointing at `testTarget`, and measures TTFB /
// throughput of the response the remote server relays back.

function testVlessConnection({
  candidateIp,
  candidatePort,
  config,
  fragmentPreset = "none",
  testTarget = { host: "speed.cloudflare.com", port: 80, path: "/__down?bytes=131072" },
  timeoutMs = 6000,
}) {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    let ttfbMs = null;
    let bytesReceived = 0;
    let resolved = false;
    let tcpConnectedAt = null;

    const done = (result) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(hardTimeout);
      try {
        rawSocket.destroy();
      } catch (_) {}
      resolve(result);
    };

    const hardTimeout = setTimeout(
      () => done({ success: false, error: "timeout" }),
      timeoutMs
    );

    const rawSocket = net.connect({ host: candidateIp, port: candidatePort });

    rawSocket.on("error", (err) =>
      done({ success: false, error: err.message })
    );

    rawSocket.on("connect", () => {
      tcpConnectedAt = process.hrtime.bigint();
      const preset = FRAGMENT_PRESETS[fragmentPreset] || null;
      wrapSocketWithFragment(rawSocket, preset);

      const tlsSocket = tls.connect({
        socket: rawSocket,
        servername: config.sni,
        rejectUnauthorized: true,
      });

      tlsSocket.on("error", (err) =>
        done({ success: false, error: `tls: ${err.message}` })
      );

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
            return done({
              success: false,
              error: `ws upgrade rejected: ${statusLine.trim()}`,
            });
          }
          phase = "vless-response";
          const header = buildVlessHeader(
            config.uuid,
            testTarget.host,
            testTarget.port
          );
          const payload = Buffer.from(
            `GET ${testTarget.path} HTTP/1.1\r\nHost: ${testTarget.host}\r\nConnection: close\r\n\r\n`
          );
          tlsSocket.write(wsFrame(Buffer.concat([header, payload])));
          return;
        }

        // Any data after the VLESS+WS handshake counts toward TTFB/throughput.
        if (ttfbMs === null) {
          const now = process.hrtime.bigint();
          ttfbMs = Number(now - start) / 1e6;
        }
        const unwrapped = unwrapWsFrame(chunk) || chunk;
        bytesReceived += unwrapped.length;
      });

      tlsSocket.on("close", () => {
        if (bytesReceived > 0) {
          const totalMs = Number(process.hrtime.bigint() - start) / 1e6;
          const throughputMbps =
            (bytesReceived * 8) / 1000 / Math.max(totalMs, 1);
          done({
            success: true,
            ttfbMs: Math.round(ttfbMs * 10) / 10,
            throughputMbps: Math.round(throughputMbps * 100) / 100,
            bytesReceived,
          });
        }
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
