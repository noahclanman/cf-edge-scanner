// pages/api/proxytest.js
import { parseVlessLink, testVlessConnection } from "../../lib/vless";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", ["POST"]);
    return res.status(405).end("Method not allowed");
  }

  const {
    ip,
    port,
    link, // vless:// share link
    fragmentPreset = "none",
    testTarget,
  } = req.body || {};

  if (!ip || !port || !link) {
    return res.status(400).json({ error: "ip, port, and link are required" });
  }

  if (link.startsWith("vmess://")) {
    return res.status(400).json({
      error:
        "VMess isn't implemented yet (its AEAD-encrypted header needs more crypto plumbing than VLESS). Use a vless:// link for now -- see README.",
    });
  }

  let config;
  try {
    config = parseVlessLink(link);
  } catch (err) {
    return res.status(400).json({ error: `Invalid vless link: ${err.message}` });
  }

  if (config.security !== "tls" || config.network !== "ws") {
    return res.status(400).json({
      error:
        "This tool currently only tests VLESS over WebSocket+TLS (type=ws&security=tls), since that's what actually routes through Cloudflare's edge on 80/443/8443.",
    });
  }

  try {
    const result = await testVlessConnection({
      candidateIp: ip,
      candidatePort: port,
      config,
      fragmentPreset,
      testTarget,
    });
    return res.status(200).json(result);
  } catch (err) {
    return res.status(200).json({ success: false, error: err.message });
  }
}
