// lib/scanner.js
// TCP-connect based reachability + latency probing. Browsers/serverless
// functions can't send raw ICMP, so "ping" here is measured as TCP
// handshake round-trip time -- the standard substitute used by this
// class of tool, and a better predictor of real usability anyway since
// it reflects the actual protocol you'll be tunneling over.

const net = require("net");

function probeOnce(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    const socket = new net.Socket();
    let settled = false;

    const finish = (alive, latencyMs) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch (_) {}
      resolve({ ip, port, alive, latencyMs });
    };

    socket.setTimeout(timeoutMs);

    socket.once("connect", () => {
      const end = process.hrtime.bigint();
      const latencyMs = Number(end - start) / 1e6;
      finish(true, Math.round(latencyMs * 10) / 10);
    });

    socket.once("timeout", () => finish(false, null));
    socket.once("error", () => finish(false, null));

    socket.connect(port, ip);
  });
}

// Runs probes for a list of {ip, port} pairs with a bounded concurrency
// pool so a single serverless invocation doesn't try to open thousands
// of sockets at once and exhaust file descriptors / the function's
// own network budget.
async function scanBatch(targets, { concurrency = 60, timeoutMs = 1200 } = {}) {
  const results = [];
  let idx = 0;

  async function worker() {
    while (idx < targets.length) {
      const myIdx = idx++;
      const { ip, port } = targets[myIdx];
      const result = await probeOnce(ip, port, timeoutMs);
      results.push(result);
    }
  }

  const workers = Array.from(
    { length: Math.min(concurrency, targets.length) },
    () => worker()
  );
  await Promise.all(workers);
  return results;
}

module.exports = { probeOnce, scanBatch };
