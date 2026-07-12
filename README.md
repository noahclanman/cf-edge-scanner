# CF Edge Scanner

A single dashboard that scans Cloudflare's published IPv4 ranges for
reachable edge IPs, ranks them by TCP latency, and (optionally) verifies
the top candidates by running a real VLESS-over-WebSocket+TLS handshake
through them using your own config, with selectable TLS-fragment presets.

## How it works

1. **Reachability + latency** — `/api/scan` runs a bounded-concurrency
   TCP-connect probe against a slice of Cloudflare's IP space on the
   ports you choose (443 / 80 / 8443). "Ping" is measured as TCP
   handshake RTT (browsers/serverless can't send raw ICMP).
2. **Ranking** — results are scored from latency alone until verified;
   verified rows fold in TTFB and throughput too.
3. **VLESS verification** — click "Verify top 20 with VLESS" to run a
   real handshake through your top candidates: connects to the
   candidate IP, TLS to your original domain (SNI preserved), upgrades
   to WebSocket, sends a real VLESS request, and measures TTFB/throughput
   of the relayed response.
4. **Fragment presets** — light/medium/heavy split the initial TLS
   ClientHello into several smaller TCP writes with small delays, to
   avoid trivial DPI signature matching. This is a best-effort,
   JS-level approximation of the same technique exposed as "fragment"
   settings in tools like Xray/sing-box — not as strong as OS-level
   packet splitting, but a reasonable starting point.

## Important limitations (read before relying on this)

- **VMess is not implemented.** Its AEAD-encrypted request header needs
  meaningfully more crypto plumbing than VLESS's plain header. The API
  will reject `vmess://` links with a clear error. Happy to add it if
  you need it — it's a self-contained addition to `lib/`.
- **Only VLESS over WebSocket+TLS is supported** (`type=ws&security=tls`).
  That's what actually routes through Cloudflare's edge on 80/443/8443
  in practice; raw-TCP VLESS wouldn't be proxied by Cloudflare for
  arbitrary destinations anyway.
- **Vercel serverless changes what "Mega Mode" means.** There's no
  persistent long-running scan process — the frontend fires many short
  batch calls (250 IPs each) instead of one continuous sweep. A true
  ~3M-address scan will take considerably longer here than on a
  dedicated VPS with raw concurrency, and will use a lot of function
  invocations. The depth presets default to bounded numbers (3k / 30k /
  300k) rather than the literal full range — use the custom depth field
  to go further once you've checked your plan's limits.
- **Function timeouts.** `vercel.json` requests up to 60s for `/api/scan`.
  Hobby-plan accounts may be capped lower regardless — check your plan
  in the Vercel dashboard and adjust `BATCH_SIZE` in `pages/index.js`
  and `maxDuration` in `vercel.json` accordingly.
- **This scans Cloudflare's own infrastructure.** Keep concurrency and
  batch pacing reasonable — it's read-only TCP-connect traffic against
  IPs Cloudflare designed to receive public connections on, but it's
  still meaningful volume in Mega Mode.

## Local development

```bash
npm install
npm run dev
# open http://localhost:3000
```

## Deploy to Vercel

```bash
npm install -g vercel   # if you don't have it
vercel
```

Or connect the repo through the Vercel dashboard — no environment
variables are required for the base functionality.

## Project layout

```
pages/
  index.js          the dashboard (single page)
  api/ranges.js      Cloudflare CIDR index + slicing
  api/scan.js        batched TCP reachability/latency probe
  api/proxytest.js   VLESS handshake verification
lib/
  cloudflareRanges.js  CIDR expansion + pagination
  scanner.js           TCP probe + concurrency pool
  vless.js             VLESS client, link parser, fragment presets
```
