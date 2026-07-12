// pages/api/scan.js
import { buildRangeIndex, fetchCloudflareRanges, sliceIps } from "../../lib/cloudflareRanges";
import { scanBatch } from "../../lib/scanner";

let cachedIndex = null;
let cachedAt = 0;
const CACHE_TTL_MS = 1000 * 60 * 60;

async function getIndex() {
  const now = Date.now();
  if (cachedIndex && now - cachedAt < CACHE_TTL_MS) return cachedIndex;
  const cidrList = await fetchCloudflareRanges();
  cachedIndex = buildRangeIndex(cidrList);
  cachedAt = now;
  return cachedIndex;
}

// Keep each invocation's work bounded well under typical Vercel function
// time limits. The frontend is responsible for orchestrating many of
// these batch calls to cover a full scan / Mega Mode.
const MAX_IPS_PER_CALL = 400;
const MAX_PORTS = 3;

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", ["POST"]);
    return res.status(405).end("Method not allowed");
  }

  const {
    offset = 0,
    count = 200,
    ports = [443],
    concurrency = 60,
    timeoutMs = 1200,
  } = req.body || {};

  const safeCount = Math.min(count, MAX_IPS_PER_CALL);
  const safePorts = ports.slice(0, MAX_PORTS);

  const index = await getIndex();
  const ips = sliceIps(index, offset, safeCount);

  const targets = [];
  for (const ip of ips) {
    for (const port of safePorts) {
      targets.push({ ip, port });
    }
  }

  const started = Date.now();
  const results = await scanBatch(targets, { concurrency, timeoutMs });
  const durationMs = Date.now() - started;

  const alive = results.filter((r) => r.alive);

  return res.status(200).json({
    offset,
    scanned: ips.length,
    probed: targets.length,
    aliveCount: alive.length,
    durationMs,
    results: alive.sort((a, b) => a.latencyMs - b.latencyMs),
  });
}
