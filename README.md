# CF Edge Scanner

A single dashboard that scans Cloudflare's published IPv4 ranges for
reachable edge IPs, ranks them by TCP latency, and (optionally) verifies
the top candidates by running a real VLESS-over-WebSocket+TLS handshake
through them using your own config, with selectable TLS-fragment presets.

## About

Cloudflare's DNS hands you whatever edge IP is convenient for *them*,
not necessarily the fastest one reachable from *you*. This tool scans
Cloudflare's published ranges directly, ranks reachable IPs by real TCP
latency, and — the part that actually matters — verifies your specific
VLESS config by running a real handshake through the candidate and
confirming data actually flows, not just that the port is open.

### Pros

- **Real measurements, not simulated.** TCP reachability and latency
  come from actual socket connections. VLESS verification does a
  genuine TLS+WebSocket+VLESS handshake and only calls it "verified" if
  a 2xx response with a real chunk of the requested bytes comes back —
  a bare handshake ack isn't enough.
- **Two independent levers, not conflated.** Edge selection (speed)
  and fragment presets (firewall resistance) are separated in the UI,
  because they trade off in opposite directions — you can optimize for
  one without blindly paying the cost of the other.
- **Zero server to run.** Deploys to Vercel's free tier; nothing to
  patch or keep alive.
- **Own it.** Open source, self-hostable, no telemetry, editable to
  your own protocol/transport needs.
- **Usable at scale without crashing the tab.** Handles large result
  sets with capped rendering, collapsible sections, and full CSV export.

### Cons / honest limitations

- **Measures from Vercel's datacenter, not your device.** "Fastest"
  here means fastest from Vercel's network position — genuinely
  useful, but not the same question as "fastest from my home
  connection." A location mismatch is inherent to any
  serverless-hosted version of this idea.
- **VLESS only** — VMess needs AEAD crypto plumbing not yet built.
- **WebSocket+TLS transport only** (no gRPC/raw-TCP), since that's what
  actually routes through Cloudflare's edge anyway.
- **Fragment presets are JS-level**, not OS-level packet splitting —
  real firewall resistance, but not as strong as dedicated tools that
  manipulate packets below the application layer.
- **"Mega Mode" is genuinely slower on serverless** than a dedicated
  VPS with raw concurrency — batched by design, bounded by default.
- **Single-user tool**, no persistent history/database — results live
  for the session, export CSV if you want to keep them.

### Real use cases

- You're running your own V2Ray/Xray server behind Cloudflare in a
  country where the default-resolved edge IP is throttled or blocked,
  and you want to manually pin a working one.
- You maintain a personal or small-group proxy and want to
  periodically check which edges are fastest/still reachable.
- You're diagnosing whether a specific Cloudflare PoP is being
  selectively blocked, by comparing which candidates pass full
  verification vs. which stall or get rejected.
- You want a lightweight, self-hosted alternative to community
  CF-IP-scanner scripts, deployable in one `vercel` command instead of
  running a script locally.

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
