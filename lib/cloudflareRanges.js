// lib/cloudflareRanges.js
// Fetches Cloudflare's published IPv4 ranges and provides utilities to
// expand CIDR blocks into individual addresses for scanning, without
// materializing millions of strings in memory at once.

const CF_V4_URL = "https://www.cloudflare.com/ips-v4";

// Fallback list (Cloudflare's ranges as of early 2026) used only if the
// live fetch fails, so the tool still works offline / in dev.
const FALLBACK_V4 = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
];

export async function fetchCloudflareRanges() {
  try {
    const res = await fetch(CF_V4_URL, { cache: "no-store" });
    if (!res.ok) throw new Error(`Cloudflare returned ${res.status}`);
    const text = await res.text();
    const lines = text
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    if (lines.length === 0) throw new Error("empty response");
    return lines;
  } catch (err) {
    return FALLBACK_V4;
  }
}

// Convert "a.b.c.d/n" into a numeric [start, end] range (inclusive), as
// 32-bit unsigned integers, so huge blocks can be indexed without
// generating every string upfront.
function cidrToRange(cidr) {
  const [ip, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr, 10);
  const octets = ip.split(".").map(Number);
  const base =
    ((octets[0] << 24) >>> 0) +
    (octets[1] << 16) +
    (octets[2] << 8) +
    octets[3];
  const size = Math.pow(2, 32 - prefix);
  const start = base >>> 0;
  const end = (start + size - 1) >>> 0;
  return { start, end, size };
}

function intToIp(int) {
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255,
  ].join(".");
}

// Build an index of all blocks with cumulative offsets so we can compute
// total size and slice out an arbitrary [offset, offset+count) window of
// IP addresses on demand -- this is what makes batched scanning + "Mega
// Mode" pagination possible without ever holding all ~3M addresses at once.
export function buildRangeIndex(cidrList) {
  let cumulative = 0;
  const blocks = cidrList.map((cidr) => {
    const { start, end, size } = cidrToRange(cidr);
    const block = { cidr, start, end, size, offset: cumulative };
    cumulative += size;
    return block;
  });
  return { blocks, total: cumulative };
}

export function sliceIps(index, offset, count) {
  const result = [];
  let remaining = count;
  let pos = offset;
  for (const block of index.blocks) {
    const blockEnd = block.offset + block.size;
    if (pos >= blockEnd) continue;
    if (remaining <= 0) break;
    const withinBlockStart = pos - block.offset;
    const intStart = block.start + withinBlockStart;
    const available = block.size - withinBlockStart;
    const take = Math.min(available, remaining);
    for (let i = 0; i < take; i++) {
      result.push(intToIp(intStart + i));
    }
    pos += take;
    remaining -= take;
    if (remaining <= 0) break;
  }
  return result;
}
