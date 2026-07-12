import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const PORT_OPTIONS = [443, 80, 8443];
const MODE_PRESETS = {
  quick: { label: "Quick", count: 3000 },
  full: { label: "Full", count: 30000 },
  mega: { label: "Mega", count: 300000 },
};
const BATCH_SIZE = 250;
const PARALLEL_BATCHES = 4;

const FRAGMENT_INFO = {
  none: "No handshake splitting. Use this if connections already work fine — pure speed, zero added overhead.",
  light: "2 small chunks, ~8ms delay. Mild resistance to basic firewalls, barely any latency cost.",
  medium: "4 chunks, ~20ms delay. Good default if connections get blocked or reset occasionally.",
  heavy: "8 tiny chunks, ~45ms delay. Most resistant to blocking, but the slowest of the four — use only if Medium still gets blocked.",
};

function scanScoreOf(row) {
  return Math.round(1000 / (1 + row.latencyMs));
}

function proxyScoreOf(row) {
  if (row.ttfbMs == null) return null;
  const pingPart = 1000 / (1 + row.latencyMs);
  const ttfbPart = 1000 / (1 + row.ttfbMs);
  const speedPart = (row.throughputMbps || 0) * 10;
  return Math.round(pingPart * 0.3 + ttfbPart * 0.4 + speedPart * 0.3);
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
  const [testTargetPort, setTestTargetPort] = useState(80);
  const [testTargetPath, setTestTargetPath] = useState("/__down?bytes=131072");
  const [verifyCount, setVerifyCount] = useState(20);

  const [scanning, setScanning] = useState(false);
  const [testingTop, setTestingTop] = useState(false);
  const [progress, setProgress] = useState({ scanned: 0, alive: 0, target: 0 });
  const [rows, setRows] = useState(new Map());
  const [scanSort, setScanSort] = useState({ key: "latencyMs", dir: "asc" });
  const [vlessSort, setVlessSort] = useState({ key: "proxyScore", dir: "desc" });
  const [scanCollapsed, setScanCollapsed] = useState(false);
  const [vlessCollapsed, setVlessCollapsed] = useState(false);
  const [error, setError] = useState(null);

  const scrollToId = (id) => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  };

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
        const merged = { ...existing, ...r, tested: existing.tested || false };
        merged.scanScore = scanScoreOf(merged);
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

  const testTop = useCallback(async () => {
    if (!vlessLink.trim()) {
      setError("Paste a vless:// link before running proxy tests.");
      return;
    }
    setError(null);
    setTestingTop(true);
    const n = Math.max(1, parseInt(verifyCount, 10) || 20);
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
            testTarget: {
              host: testTargetHost,
              port: parseInt(testTargetPort, 10) || 80,
              path: testTargetPath,
            },
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
            tested: true,
            ttfbMs: data.success ? data.ttfbMs : existing.ttfbMs ?? null,
            throughputMbps: data.success ? data.throughputMbps : existing.throughputMbps ?? null,
            proxyStatus: data.success ? "verified" : "failed",
            proxyError: data.success ? null : data.error,
          };
          merged.proxyScore = proxyScoreOf(merged);
          next.set(key, merged);
          return next;
        });
      } catch (e) {
        setError(e.message);
      }
    }
    setTestingTop(false);
  }, [rows, vlessLink, fragmentPreset, testTargetHost, testTargetPort, testTargetPath, verifyCount]);

  const sortedScanRows = useMemo(() => {
    const arr = Array.from(rows.values());
    arr.sort((a, b) => {
      const av = a[scanSort.key] ?? -Infinity;
      const bv = b[scanSort.key] ?? -Infinity;
      return scanSort.dir === "asc" ? av - bv : bv - av;
    });
    return arr;
  }, [rows, scanSort]);

  const sortedVlessRows = useMemo(() => {
    const arr = Array.from(rows.values()).filter((r) => r.tested);
    arr.sort((a, b) => {
      const av = a[vlessSort.key] ?? -Infinity;
      const bv = b[vlessSort.key] ?? -Infinity;
      return vlessSort.dir === "asc" ? av - bv : bv - av;
    });
    return arr;
  }, [rows, vlessSort]);

  const onScanSort = (key) => {
    setScanSort((prev) =>
      prev.key === key ? { key, dir: prev.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }
    );
  };

  const onVlessSort = (key) => {
    setVlessSort((prev) =>
      prev.key === key ? { key, dir: prev.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" }
    );
  };

  const exportCsv = (kind) => {
    let header, rowsToExport, mapFn, filename;
    if (kind === "scan") {
      header = "ip,port,latency_ms,scan_score\n";
      rowsToExport = sortedScanRows;
      mapFn = (r) => [r.ip, r.port, r.latencyMs, r.scanScore].join(",");
      filename = "cf-scan-results.csv";
    } else {
      header = "ip,port,latency_ms,ttfb_ms,throughput_mbps,proxy_score,status\n";
      rowsToExport = sortedVlessRows;
      mapFn = (r) =>
        [r.ip, r.port, r.latencyMs, r.ttfbMs ?? "", r.throughputMbps ?? "", r.proxyScore ?? "", r.proxyStatus].join(",");
      filename = "cf-vless-verified-results.csv";
    }
    const body = rowsToExport.map(mapFn).join("\n");
    const blob = new Blob([header + body], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
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

      {/* --- Scan config --- */}
      <section style={panelStyle}>
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

      {/* --- What scan vs verify actually do --- */}
      <div style={infoBoxStyle}>
        <strong style={{ color: "var(--amber)" }}>Scanning</strong> finds your fastest reachable
        Cloudflare edge IP — pure speed, no tradeoff. <strong style={{ color: "var(--teal)" }}>Verifying</strong>{" "}
        with your VLESS link confirms the tunnel actually works through that IP and measures real TTFB/speed.{" "}
        <strong>Fragment presets</strong> are a separate, independent lever: they make the handshake harder for a
        firewall to block, at the cost of a little latency — only turn them up if connections are actually getting
        blocked, not for speed.
      </div>

      {/* --- VLESS verification config --- */}
      <section style={panelStyle}>
        <Field label="VLESS link (vless://...)">
          <input
            placeholder="vless://uuid@domain:443?type=ws&security=tls&path=/ws&host=domain#name"
            value={vlessLink}
            onChange={(e) => setVlessLink(e.target.value)}
            style={inputStyle()}
          />
        </Field>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 18, marginTop: 18 }}>
          <Field label="Fragment preset">
            <select value={fragmentPreset} onChange={(e) => setFragmentPreset(e.target.value)} style={inputStyle()}>
              <option value="none">None</option>
              <option value="light">Light</option>
              <option value="medium">Medium</option>
              <option value="heavy">Heavy</option>
            </select>
            <p style={captionStyle}>{FRAGMENT_INFO[fragmentPreset]}</p>
          </Field>

          <Field label="Verify top N candidates">
            <input
              type="number"
              min={1}
              max={200}
              value={verifyCount}
              onChange={(e) => setVerifyCount(e.target.value)}
              style={inputStyle()}
            />
            <p style={captionStyle}>How many of your fastest-pinging scan results to actually test with a real VLESS handshake.</p>
          </Field>
        </div>

        <div style={{ marginTop: 18 }}>
          <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 6 }}>Test target</div>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 2fr", gap: 10 }}>
            <input placeholder="host" value={testTargetHost} onChange={(e) => setTestTargetHost(e.target.value)} style={inputStyle()} />
            <input
              type="number"
              placeholder="port"
              value={testTargetPort}
              onChange={(e) => setTestTargetPort(e.target.value)}
              style={inputStyle()}
            />
            <input placeholder="path" value={testTargetPath} onChange={(e) => setTestTargetPath(e.target.value)} style={inputStyle()} />
          </div>
          <p style={captionStyle}>
            Your VLESS server fetches this URL on your behalf through the tunnel, so TTFB/speed reflect something
            real. The default (speed.cloudflare.com) is Cloudflare's own public test endpoint — swap it only for
            another host that serves real downloadable bytes at the given path.
          </p>
        </div>

        <div style={{ marginTop: 14, display: "flex", gap: 12, alignItems: "center" }}>
          <button onClick={testTop} disabled={testingTop || rows.size === 0} style={secondaryButtonStyle}>
            {testingTop ? "Verifying candidates…" : `Verify top ${verifyCount} with VLESS`}
          </button>
        </div>
      </section>

      {error && <div style={errorBoxStyle}>{error}</div>}

      {/* --- Result 1: scan results --- */}
      <ResultsTable
        id="scan-results-section"
        title={`SCAN RESULTS (${sortedScanRows.length})`}
        rows={sortedScanRows}
        onSort={onScanSort}
        onExport={() => exportCsv("scan")}
        emptyMessage="No results yet. Start a scan to populate this table."
        collapsed={scanCollapsed}
        onToggleCollapse={() => setScanCollapsed((c) => !c)}
        jumpLabel={sortedVlessRows.length > 0 ? "↓ VLESS results" : null}
        onJump={() => scrollToId("vless-results-section")}
        columns={[
          { key: "scanScore", label: "Score" },
          { key: "ip", label: "IP" },
          { key: "port", label: "Port" },
          { key: "latencyMs", label: "Ping (ms)", fmt: (v) => v?.toFixed(1) },
        ]}
      />

      {/* --- Result 2: vless verified results --- */}
      <div style={{ marginTop: 20 }}>
        <ResultsTable
          id="vless-results-section"
          title={`VLESS VERIFIED RESULTS (${sortedVlessRows.length})`}
          rows={sortedVlessRows}
          onSort={onVlessSort}
          onExport={() => exportCsv("vless")}
          emptyMessage="No candidates verified yet. Run 'Verify top N with VLESS' above."
          collapsed={vlessCollapsed}
          onToggleCollapse={() => setVlessCollapsed((c) => !c)}
          jumpLabel="↑ Scan results"
          onJump={() => scrollToId("scan-results-section")}
          columns={[
            { key: "proxyScore", label: "Score" },
            { key: "ip", label: "IP" },
            { key: "port", label: "Port" },
            { key: "latencyMs", label: "Ping (ms)", fmt: (v) => v?.toFixed(1) },
            { key: "ttfbMs", label: "TTFB (ms)", fmt: (v) => (v != null ? v.toFixed(1) : "—") },
            { key: "throughputMbps", label: "Speed (Mbps)", fmt: (v) => v ?? "—" },
            { key: "proxyStatus", label: "Status", statusColumn: true },
          ]}
        />
      </div>
    </div>
  );
}

function Chevron({ collapsed }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{
        transform: collapsed ? "rotate(-90deg)" : "rotate(0deg)",
        transition: "transform 0.2s ease",
        flexShrink: 0,
      }}
      aria-hidden="true"
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

function ResultsTable({
  id,
  title,
  rows,
  onSort,
  onExport,
  emptyMessage,
  columns,
  collapsed,
  onToggleCollapse,
  jumpLabel,
  onJump,
}) {
  return (
    <section id={id} style={{ ...panelStyle, padding: 0, overflow: "hidden" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "14px 18px",
          borderBottom: collapsed ? "none" : "1px solid var(--panel-border)",
        }}
      >
        <button
          onClick={onToggleCollapse}
          aria-expanded={!collapsed}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            background: "transparent",
            border: "none",
            color: "var(--text)",
            cursor: "pointer",
            padding: "4px 4px 4px 0",
          }}
        >
          <Chevron collapsed={collapsed} />
          <strong style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>{title}</strong>
        </button>
        <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
          {jumpLabel && (
            <button onClick={onJump} style={jumpLinkStyle}>
              {jumpLabel}
            </button>
          )}
          <button onClick={onExport} disabled={rows.length === 0} style={secondaryButtonStyle}>
            Export CSV
          </button>
        </div>
      </div>

      {/* Pure CSS collapse: animating grid-template-rows between 0fr/1fr
          lets the browser interpolate to the content's natural height with
          no JS height measurement, so there's no layout-thrash/jank even
          on a table with hundreds of rows. */}
      <div
        style={{
          display: "grid",
          gridTemplateRows: collapsed ? "0fr" : "1fr",
          transition: "grid-template-rows 0.22s ease",
        }}
      >
        <div style={{ overflow: "hidden", minHeight: 0 }}>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "var(--font-mono)", fontSize: 13 }}>
              <thead>
                <tr style={{ textAlign: "left", color: "var(--muted)" }}>
                  {columns.map((c) => (
                    <Th key={c.key} onClick={() => onSort(c.key)}>
                      {c.label}
                    </Th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, 500).map((r) => (
                  <tr key={`${r.ip}:${r.port}`} style={{ borderTop: "1px solid var(--panel-border)" }}>
                    {columns.map((c) => (
                      <td key={c.key} style={{ ...td, color: c.statusColumn ? statusColor(r[c.key]) : undefined }}>
                        {c.fmt ? c.fmt(r[c.key]) : r[c.key]}
                      </td>
                    ))}
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={columns.length} style={{ ...td, color: "var(--muted)", textAlign: "center", padding: 30 }}>
                      {emptyMessage}
                    </td>
                  </tr>
                )}
                {rows.length > 500 && (
                  <tr>
                    <td colSpan={columns.length} style={{ ...td, color: "var(--muted)", textAlign: "center", padding: 14 }}>
                      Showing top 500 of {rows.length.toLocaleString()} — export CSV for the full set.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
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
    <th onClick={onClick} style={{ padding: "8px 14px", cursor: "pointer", userSelect: "none" }}>
      {children}
    </th>
  );
}

const td = { padding: "8px 14px" };

function statusColor(status) {
  if (status === "verified") return "var(--teal)";
  if (status === "failed") return "var(--rose)";
  return "var(--text)";
}

const panelStyle = {
  background: "var(--panel)",
  border: "1px solid var(--panel-border)",
  borderRadius: 10,
  padding: 20,
  marginBottom: 20,
};

const infoBoxStyle = {
  background: "rgba(45,212,191,0.06)",
  border: "1px solid rgba(45,212,191,0.25)",
  borderRadius: 8,
  padding: "12px 16px",
  marginBottom: 20,
  fontSize: 13,
  lineHeight: 1.6,
  color: "var(--text)",
};

const errorBoxStyle = {
  background: "rgba(244,63,94,0.1)",
  border: "1px solid var(--rose)",
  color: "var(--rose)",
  borderRadius: 8,
  padding: "10px 14px",
  marginBottom: 16,
  fontSize: 13,
};

const captionStyle = {
  margin: "8px 0 0",
  fontSize: 12,
  color: "var(--muted)",
  lineHeight: 1.5,
  fontFamily: "var(--font-sans)",
};

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

const jumpLinkStyle = {
  background: "transparent",
  border: "none",
  color: "var(--teal)",
  cursor: "pointer",
  fontSize: 12,
  fontFamily: "var(--font-mono)",
  padding: 0,
};
