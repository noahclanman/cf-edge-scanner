import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const PORT_OPTIONS = [443, 80, 8443];
const MODE_PRESETS = {
  quick: { label: "Quick", count: 3000 },
  full: { label: "Full", count: 30000 },
  mega: { label: "Mega", count: 300000 },
};
const BATCH_SIZE = 250;
const PARALLEL_BATCHES = 4;

function scoreOf(row) {
  const pingScore = 1000 / (1 + row.latencyMs);
  if (row.ttfbMs == null) return Math.round(pingScore);
  const ttfbScore = 1000 / (1 + row.ttfbMs);
  const speedScore = (row.throughputMbps || 0) * 10;
  return Math.round(pingScore * 0.4 + ttfbScore * 0.3 + speedScore * 0.3);
}

function SweepRing({ active, pct }) {
  const r = 26;
  const c = 2 * Math.PI * r;
  const offset = c - (pct / 100) * c;
  return (
    <svg width="64" height="64" viewBox="0 0 64 64" aria-hidden="true">
      <circle cx="32" cy="32" r={r} fill="none" stroke="#1e252d" strokeWidth="4" />
      <circle
        cx="32"
        cy="32"
        r={r}
        fill="none"
        stroke={active ? "#ffb020" : "#2dd4bf"}
        strokeWidth="4"
        strokeDasharray={c}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform="rotate(-90 32 32)"
        style={{ transition: "stroke-dashoffset 0.3s ease" }}
      />
      {active && (
        <g style={{ transformOrigin: "32px 32px", animation: "spin 1.4s linear infinite" }}>
          <line x1="32" y1="32" x2="32" y2="8" stroke="#ffb020" strokeWidth="2" opacity="0.6" />
        </g>
      )}
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </svg>
  );
}

export default function Home() {
  const [rangeTotal, setRangeTotal] = useState(null);
  const [mode, setMode] = useState("quick");
  const [customDepth, setCustomDepth] = useState("");
  const [ports, setPorts] = useState([443]);
  const [concurrency, setConcurrency] = useState(60);
  const [vlessLink, setVlessLink] = useState("");
  const [fragmentPreset, setFragmentPreset] = useState("medium");
  const [testTargetHost, setTestTargetHost] = useState("speed.cloudflare.com");

  const [scanning, setScanning] = useState(false);
  const [testingTop, setTestingTop] = useState(false);
  const [progress, setProgress] = useState({ scanned: 0, alive: 0, target: 0 });
  const [rows, setRows] = useState(new Map());
  const [sort, setSort] = useState({ key: "score", dir: "desc" });
  const [error, setError] = useState(null);

  const stopRef = useRef(false);

  useEffect(() => {
    fetch("/api/ranges")
      .then((r) => r.json())
      .then((d) => setRangeTotal(d.total))
      .catch(() => setRangeTotal(null));
  }, []);

  const targetCount = useMemo(() => {
    const custom = parseInt(customDepth, 10);
    if (!isNaN(custom) && custom > 0) return custom;
    return MODE_PRESETS[mode].count;
  }, [mode, customDepth]);

  const togglePort = (p) => {
    setPorts((prev) =>
      prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p].sort((a, b) => a - b)
    );
  };

  const mergeResults = useCallback((batchResults) => {
    setRows((prev) => {
      const next = new Map(prev);
      for (const r of batchResults) {
        const key = `${r.ip}:${r.port}`;
        const existing = next.get(key) || {};
        const merged = { ...existing, ...r, status: "alive" };
        merged.score = scoreOf(merged);
        next.set(key, merged);
      }
      return next;
    });
  }, []);

  const startScan = useCallback(async () => {
    setError(null);
    setRows(new Map());
    setProgress({ scanned: 0, alive: 0, target: targetCount });
    stopRef.current = false;
    setScanning(true);

    const offsets = [];
    for (let o = 0; o < targetCount; o += BATCH_SIZE) offsets.push(o);

    let cursor = 0;
    let totalScanned = 0;
    let totalAlive = 0;

    async function worker() {
      while (cursor < offsets.length) {
        if (stopRef.current) return;
        const offset = offsets[cursor++];
        const count = Math.min(BATCH_SIZE, targetCount - offset);
        try {
          const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ offset, count, ports, concurrency, timeoutMs: 1200 }),
          });
          if (!res.ok) throw new Error(`scan batch failed (${res.status})`);
          const data = await res.json();
          mergeResults(data.results);
          totalScanned += data.scanned;
          totalAlive += data.aliveCount;
          setProgress({ scanned: totalScanned, alive: totalAlive, target: targetCount });
        } catch (e) {
          setError(e.message);
        }
      }
    }

    const workers = Array.from({ length: PARALLEL_BATCHES }, () => worker());
    await Promise.all(workers);
    setScanning(false);
  }, [targetCount, ports, concurrency, mergeResults]);

  const stopScan = () => {
    stopRef.current = true;
    setScanning(false);
  };

  const testTop = useCallback(
    async (n = 20) => {
      if (!vlessLink.trim()) {
        setError("Paste a vless:// link before running proxy tests.");
        return;
      }
      setError(null);
      setTestingTop(true);
      const candidates = Array.from(rows.values())
        .sort((a, b) => a.latencyMs - b.latencyMs)
        .slice(0, n);

      for (const c of candidates) {
        if (stopRef.current) break;
        try {
          const res = await fetch("/api/proxytest", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              ip: c.ip,
              port: c.port,
              link: vlessLink.trim(),
              fragmentPreset,
              testTarget: { host: testTargetHost, port: 80, path: "/__down?bytes=131072" },
            }),
          });
          const data = await res.json();
          setRows((prev) => {
            const next = new Map(prev);
            const key = `${c.ip}:${c.port}`;
            const existing = next.get(key);
            if (!existing) return prev;
            const merged = {
              ...existing,
              ttfbMs: data.success ? data.ttfbMs : existing.ttfbMs,
              throughputMbps: data.success ? data.throughputMbps : existing.throughputMbps,
              status: data.success ? "verified" : "proxy-failed",
              proxyError: data.success ? null : data.error,
            };
            merged.score = scoreOf(merged);
            next.set(key, merged);
            return next;
          });
        } catch (e) {
          setError(e.message);
        }
      }
      setTestingTop(false);
    },
    [rows, vlessLink, fragmentPreset, testTargetHost]
  );

  const sortedRows = useMemo(() => {
    const arr = Array.from(rows.values());
    arr.sort((a, b) => {
      const av = a[sort.key] ?? -Infinity;
      const bv = b[sort.key] ?? -Infinity;
      return sort.dir === "asc" ? av - bv : bv - av;
    });
    return arr;
  }, [rows, sort]);

  const onSort = (key) => {
    setSort((prev) =>
      prev.key === key ? { key, dir: prev.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" }
    );
  };

  const exportCsv = () => {
    const header = "ip,port,latency_ms,ttfb_ms,throughput_mbps,score,status\n";
    const body = sortedRows
      .map((r) =>
        [r.ip, r.port, r.latencyMs, r.ttfbMs ?? "", r.throughputMbps ?? "", r.score, r.status].join(",")
      )
      .join("\n");
    const blob = new Blob([header + body], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "cf-scan-results.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  const pct = progress.target ? Math.min(100, (progress.scanned / progress.target) * 100) : 0;

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: "32px 20px 80px" }}>
      <header style={{ display: "flex", alignItems: "center", gap: 20, marginBottom: 28 }}>
        <SweepRing active={scanning} pct={pct} />
        <div>
          <h1
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: 22,
              letterSpacing: 1,
              margin: 0,
              color: "var(--text)",
            }}
          >
            CF EDGE SCANNER
          </h1>
          <p style={{ margin: "4px 0 0", color: "var(--muted)", fontSize: 13 }}>
            {rangeTotal ? `${rangeTotal.toLocaleString()} Cloudflare IPv4 addresses indexed` : "Loading Cloudflare ranges…"}
            {" · "}
            {progress.scanned.toLocaleString()} scanned · {progress.alive.toLocaleString()} alive
          </p>
        </div>
      </header>

      <section
        style={{
          background: "var(--panel)",
          border: "1px solid var(--panel-border)",
          borderRadius: 10,
          padding: 20,
          marginBottom: 20,
        }}
      >
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 18 }}>
          <Field label="Scan depth">
            <div style={{ display: "flex", gap: 8 }}>
              {Object.entries(MODE_PRESETS).map(([key, p]) => (
                <button
                  key={key}
                  onClick={() => {
                    setMode(key);
                    setCustomDepth("");
                  }}
                  disabled={scanning}
                  style={pillStyle(mode === key && !customDepth)}
                >
                  {p.label}
                </button>
              ))}
            </div>
            <input
              placeholder="custom # of IPs"
              value={customDepth}
              onChange={(e) => setCustomDepth(e.target.value)}
              disabled={scanning}
              style={inputStyle({ marginTop: 8 })}
            />
          </Field>

          <Field label="Ports">
            <div style={{ display: "flex", gap: 8 }}>
              {PORT_OPTIONS.map((p) => (
                <button
                  key={p}
                  onClick={() => togglePort(p)}
                  disabled={scanning}
                  style={pillStyle(ports.includes(p))}
                >
                  {p}
                </button>
              ))}
            </div>
          </Field>

          <Field label={`Concurrency: ${concurrency}`}>
            <input
              type="range"
              min={10}
              max={200}
              value={concurrency}
              onChange={(e) => setConcurrency(parseInt(e.target.value, 10))}
              disabled={scanning}
              style={{ width: "100%" }}
            />
          </Field>
        </div>

        <div style={{ display: "flex", gap: 12, marginTop: 18 }}>
          {!scanning ? (
            <button onClick={startScan} style={primaryButtonStyle}>
              Start scan
            </button>
          ) : (
            <button onClick={stopScan} style={dangerButtonStyle}>
              Stop
            </button>
          )}
          {progress.target > 0 && (
            <div style={{ flex: 1, alignSelf: "center" }}>
              <div style={{ height: 6, background: "#1e252d", borderRadius: 3, overflow: "hidden" }}>
                <div
                  style={{
                    height: "100%",
                    width: `${pct}%`,
                    background: scanning ? "var(--amber)" : "var(--teal)",
                    transition: "width 0.3s ease",
                  }}
                />
              </div>
            </div>
          )}
        </div>
      </section>

      <section
        style={{
          background: "var(--panel)",
          border: "1px solid var(--panel-border)",
          borderRadius: 10,
          padding: 20,
          marginBottom: 20,
        }}
      >
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 18 }}>
          <Field label="VLESS link (vless://...)">
            <input
              placeholder="vless://uuid@domain:443?type=ws&security=tls&path=/ws&host=domain#name"
              value={vlessLink}
              onChange={(e) => setVlessLink(e.target.value)}
              style={inputStyle()}
            />
          </Field>
          <Field label="Fragment preset">
            <select
              value={fragmentPreset}
              onChange={(e) => setFragmentPreset(e.target.value)}
              style={inputStyle()}
            >
              <option value="none">None</option>
              <option value="light">Light</option>
              <option value="medium">Medium</option>
              <option value="heavy">Heavy</option>
            </select>
          </Field>
          <Field label="Test target host">
            <input
              value={testTargetHost}
              onChange={(e) => setTestTargetHost(e.target.value)}
              style={inputStyle()}
            />
          </Field>
        </div>
        <div style={{ marginTop: 14, display: "flex", gap: 12, alignItems: "center" }}>
          <button
            onClick={() => testTop(20)}
            disabled={testingTop || rows.size === 0}
            style={secondaryButtonStyle}
          >
            {testingTop ? "Testing top candidates…" : "Verify top 20 with VLESS"}
          </button>
          <span style={{ color: "var(--muted)", fontSize: 12 }}>
            Runs the real handshake through the current top-ranked reachable IPs.
          </span>
        </div>
      </section>

      {error && (
        <div
          style={{
            background: "rgba(244,63,94,0.1)",
            border: "1px solid var(--rose)",
            color: "var(--rose)",
            borderRadius: 8,
            padding: "10px 14px",
            marginBottom: 16,
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}

      <section
        style={{
          background: "var(--panel)",
          border: "1px solid var(--panel-border)",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "14px 18px",
            borderBottom: "1px solid var(--panel-border)",
          }}
        >
          <strong style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
            RESULTS ({sortedRows.length})
          </strong>
          <button onClick={exportCsv} disabled={sortedRows.length === 0} style={secondaryButtonStyle}>
            Export CSV
          </button>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "var(--font-mono)", fontSize: 13 }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--muted)" }}>
                <Th onClick={() => onSort("score")}>Score</Th>
                <Th onClick={() => onSort("ip")}>IP</Th>
                <Th onClick={() => onSort("port")}>Port</Th>
                <Th onClick={() => onSort("latencyMs")}>Ping (ms)</Th>
                <Th onClick={() => onSort("ttfbMs")}>TTFB (ms)</Th>
                <Th onClick={() => onSort("throughputMbps")}>Speed (Mbps)</Th>
                <th style={{ padding: "8px 14px" }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {sortedRows.slice(0, 500).map((r) => (
                <tr key={`${r.ip}:${r.port}`} style={{ borderTop: "1px solid var(--panel-border)" }}>
                  <td style={td}>{r.score}</td>
                  <td style={td}>{r.ip}</td>
                  <td style={td}>{r.port}</td>
                  <td style={td}>{r.latencyMs?.toFixed(1)}</td>
                  <td style={td}>{r.ttfbMs?.toFixed(1) ?? "—"}</td>
                  <td style={td}>{r.throughputMbps ?? "—"}</td>
                  <td style={{ ...td, color: statusColor(r.status) }}>{r.status}</td>
                </tr>
              ))}
              {sortedRows.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ ...td, color: "var(--muted)", textAlign: "center", padding: 30 }}>
                    No results yet. Start a scan to populate this table.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 6 }}>{label}</div>
      {children}
    </div>
  );
}

function Th({ children, onClick }) {
  return (
    <th
      onClick={onClick}
      style={{ padding: "8px 14px", cursor: "pointer", userSelect: "none" }}
    >
      {children}
    </th>
  );
}

const td = { padding: "8px 14px" };

function statusColor(status) {
  if (status === "verified") return "var(--teal)";
  if (status === "proxy-failed") return "var(--rose)";
  return "var(--text)";
}

function pillStyle(active) {
  return {
    padding: "6px 14px",
    borderRadius: 6,
    border: `1px solid ${active ? "var(--amber)" : "var(--panel-border)"}`,
    background: active ? "rgba(255,176,32,0.12)" : "transparent",
    color: active ? "var(--amber)" : "var(--text)",
    cursor: "pointer",
    fontFamily: "var(--font-mono)",
    fontSize: 13,
  };
}

function inputStyle(extra = {}) {
  return {
    width: "100%",
    padding: "8px 10px",
    borderRadius: 6,
    border: "1px solid var(--panel-border)",
    background: "#0d1116",
    color: "var(--text)",
    fontSize: 13,
    ...extra,
  };
}

const primaryButtonStyle = {
  padding: "10px 20px",
  borderRadius: 6,
  border: "1px solid var(--amber)",
  background: "var(--amber)",
  color: "#12161b",
  fontWeight: 600,
  cursor: "pointer",
};

const dangerButtonStyle = {
  ...primaryButtonStyle,
  border: "1px solid var(--rose)",
  background: "transparent",
  color: "var(--rose)",
};

const secondaryButtonStyle = {
  padding: "8px 16px",
  borderRadius: 6,
  border: "1px solid var(--panel-border)",
  background: "transparent",
  color: "var(--text)",
  cursor: "pointer",
  fontSize: 13,
};
