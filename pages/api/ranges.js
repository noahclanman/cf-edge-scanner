// pages/api/ranges.js
import { fetchCloudflareRanges, buildRangeIndex, sliceIps } from "../../lib/cloudflareRanges";

// Cache the range index in-memory for the lifetime of the warm serverless
// instance, so repeated batch requests during one scan don't each refetch
// and rebuild the index.
let cachedIndex = null;
let cachedAt = 0;
const CACHE_TTL_MS = 1000 * 60 * 60; // 1 hour

async function getIndex() {
  const now = Date.now();
  if (cachedIndex && now - cachedAt < CACHE_TTL_MS) return cachedIndex;
  const cidrList = await fetchCloudflareRanges();
  cachedIndex = buildRangeIndex(cidrList);
  cachedAt = now;
  return cachedIndex;
}

export default async function handler(req, res) {
  const index = await getIndex();

  if (req.method === "GET") {
    return res.status(200).json({
      total: index.total,
      blocks: index.blocks.map((b) => ({ cidr: b.cidr, size: b.size })),
    });
  }

  if (req.method === "POST") {
    const { offset = 0, count = 200 } = req.body || {};
    const ips = sliceIps(index, offset, count);
    return res.status(200).json({ ips, offset, count: ips.length });
  }

  res.setHeader("Allow", ["GET", "POST"]);
  return res.status(405).end("Method not allowed");
}
