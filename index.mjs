// doh-proxy.mjs
// Node.js DOH proxy that supports hosts.json override and upstream DOH forwarding.
// Usage: node doh-proxy.mjs
// Env:
//   UPSTREAM_DOH (default: https://one.one.one.one/dns-query)
//   HOSTS_FILE  (default: ./hosts.json)
//   PORT        (default: 8053)

import fs from "fs";
import http from "http";
import express from "express";
import fetch from "node-fetch"; // safe fallback; Node 18+ has global fetch
import dnsPacket from "dns-packet";
import { URL } from "url";

const PORT = process.env.PORT ? Number(process.env.PORT) : 8053;
const UPSTREAM = process.env.UPSTREAM_DOH || "https://one.one.one.one/dns-query";
const HOSTS_FILE = process.env.HOSTS_FILE || "./hosts.json";

function loadHosts() {
  try {
    const raw = fs.readFileSync(HOSTS_FILE, "utf8");
    const json = JSON.parse(raw);
    const map = new Map();
    for (const [k, v] of Object.entries(json)) {
      const key = k.toLowerCase().replace(/\.$/, "");
      if (Array.isArray(v)) map.set(key, v.map(String));
      else map.set(key, [String(v)]);
    }
    return map;
  } catch (err) {
    console.warn("Could not load hosts file:", err.message);
    return new Map();
  }
}
let hosts = loadHosts();
fs.watchFile(HOSTS_FILE, { interval: 1000 }, () => {
  console.log("Hosts file changed, reloading...");
  hosts = loadHosts();
});

function isPrivateIp(ip) {
  if (!ip || typeof ip !== "string") return false;
  const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const a = +v4[1], b = +v4[2];
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    return false;
  }
  const ipLower = ip.toLowerCase();
  if (ipLower === "::1") return true;
  if (/^f[cd]/.test(ipLower)) return true;
  if (ipLower.startsWith("fe80:")) return true;
  return false;
}

async function forwardToUpstreamWire(dnsWireBuffer, upstream = UPSTREAM) {
  const headers = {
    "content-type": "application/dns-message",
    Accept: "application/dns-message, application/dns-json, */*",
    "user-agent": "doh-proxy/1.0"
  };

  // Use POST (binary) to upstream DOH
  const res = await fetch(upstream, {
    method: "POST",
    headers,
    body: dnsWireBuffer,
    redirect: "follow",
  });

  const respHeaders = {};
  res.headers.forEach((v, k) => (respHeaders[k] = v));
  const arrayBuffer = await res.arrayBuffer();
  return { buffer: Buffer.from(arrayBuffer), status: res.status, headers: respHeaders };
}

async function forwardToUpstreamJson(name, type = "A", upstream = UPSTREAM) {
  // Try dns-json style GET; if upstream doesn't support it, this may 404/return different structure
  const u = new URL(upstream);
  u.searchParams.set("name", name);
  u.searchParams.set("type", type);
  const res = await fetch(String(u), { headers: { Accept: "application/dns-json", "user-agent": "doh-proxy/1.0" } });
  const json = await res.json().catch(() => null);
  const headers = {};
  res.headers.forEach((v, k) => (headers[k] = v));
  return { json, status: res.status, headers };
}

function buildDnsAnswerPacket(queryPacketBuffer, rrList) {
  const q = dnsPacket.decode(queryPacketBuffer);
  const response = {
    id: q.id,
    type: "response",
    flags: q.flags || dnsPacket.RECURSION_DESIRED,
    questions: q.questions,
    answers: [],
    authorities: [],
    additionals: []
  };

  for (const rr of rrList) {
    response.answers.push({
      name: rr.name,
      type: rr.type,
      ttl: rr.ttl || 300,
      class: rr.class || "IN",
      data: rr.data
    });
  }

  return dnsPacket.encode(response);
}

function questionNameAndTypeFromWire(buf) {
  try {
    const p = dnsPacket.decode(buf);
    if (!p.questions || p.questions.length === 0) return null;
    const q = p.questions[0];
    return { name: q.name.replace(/\.$/, ""), type: q.type || "A" };
  } catch (e) {
    return null;
  }
}

const app = express();

// collect raw body for any request (so wire-format POSTs are available)
app.use((req, res, next) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    req.rawBody = Buffer.concat(chunks);
    // also parse JSON if content-type is json for convenience
    const ct = (req.headers["content-type"] || "").toLowerCase();
    if (ct.includes("application/json") && req.rawBody.length) {
      try { req.body = JSON.parse(req.rawBody.toString("utf8")); } catch (e) { /* ignore */ }
    }
    next();
  });
  req.on("error", next);
});

// Helper to respond with wire format
function sendWireResponse(res, buffer) {
  res.setHeader("content-type", "application/dns-message");
  res.setHeader("content-length", buffer.length);
  res.status(200).send(buffer);
}

// Use RegExp catch-all to avoid path-to-regexp issues
app.all(/.*/, async (req, res) => {
  try {
    const accept = (req.headers.accept || "").toLowerCase();
    const wantsJson = accept.includes("application/dns-json") || req.query.name !== undefined || req.query.type !== undefined;

    // GET?dns=... (wire base64url)
    if (req.method === "GET" && req.query.dns) {
      const dnsParam = req.query.dns.toString();
      const b64 = dnsParam.replace(/-/g, "+").replace(/_/g, "/");
      const pad = b64.length % 4;
      const padded = b64 + (pad ? "=".repeat(4 - pad) : "");
      const qBuf = Buffer.from(padded, "base64");

      const qinfo = questionNameAndTypeFromWire(qBuf);
      const lowerName = qinfo ? qinfo.name.toLowerCase() : null;

      if (lowerName && hosts.has(lowerName)) {
        const ipList = hosts.get(lowerName);
        let rrList = [];
        const qType = qinfo.type || "A";
        for (const ip of ipList) {
          if (qType === "A" && ip.includes(".")) rrList.push({ name: lowerName, type: "A", ttl: 300, data: ip });
          else if (qType === "AAAA" && ip.includes(":")) rrList.push({ name: lowerName, type: "AAAA", ttl: 300, data: ip });
          else if (qType === "ANY") {
            if (ip.includes(".")) rrList.push({ name: lowerName, type: "A", ttl: 300, data: ip });
            if (ip.includes(":")) rrList.push({ name: lowerName, type: "AAAA", ttl: 300, data: ip });
          }
        }
        if (rrList.length === 0 && ipList.length > 0) {
          const first = ipList[0];
          const t = first.includes(":") ? "AAAA" : "A";
          rrList.push({ name: lowerName, type: t, ttl: 300, data: first });
        }

        const respBuf = buildDnsAnswerPacket(qBuf, rrList);

        // Forward to upstream DOH (wire) and await it (so forwarding uses DOH protocol)
        try {
          const upstreamRes = await forwardToUpstreamWire(qBuf);
          console.log(`Forwarded ${lowerName} (overrides) to upstream (wire) status=${upstreamRes.status}`);
        } catch (e) {
          console.error("Upstream forward (wire) failed:", e.message);
        }

        return sendWireResponse(res, respBuf);
      } else {
        // Not in hosts => proxy to upstream DOH (wire)
        const upstreamRes = await forwardToUpstreamWire(qBuf);
        if (upstreamRes.headers["content-type"]) res.setHeader("content-type", upstreamRes.headers["content-type"]);
        if (upstreamRes.headers["content-encoding"]) res.setHeader("content-encoding", upstreamRes.headers["content-encoding"]);
        if (upstreamRes.headers["cache-control"]) res.setHeader("cache-control", upstreamRes.headers["cache-control"]);
        res.status(upstreamRes.status).send(upstreamRes.buffer);
        return;
      }
    } else if (req.method === "POST" && (req.headers["content-type"] || "").indexOf("application/dns-message") !== -1) {
      // POST wire format
      const qBuf = req.rawBody || Buffer.alloc(0);
      const qinfo = questionNameAndTypeFromWire(qBuf);
      const lowerName = qinfo ? qinfo.name.toLowerCase() : null;

      if (lowerName && hosts.has(lowerName)) {
        const ipList = hosts.get(lowerName);
        let rrList = [];
        const qType = qinfo.type || "A";
        for (const ip of ipList) {
          if (qType === "A" && ip.includes(".")) rrList.push({ name: lowerName, type: "A", ttl: 300, data: ip });
          else if (qType === "AAAA" && ip.includes(":")) rrList.push({ name: lowerName, type: "AAAA", ttl: 300, data: ip });
          else if (qType === "ANY") {
            if (ip.includes(".")) rrList.push({ name: lowerName, type: "A", ttl: 300, data: ip });
            if (ip.includes(":")) rrList.push({ name: lowerName, type: "AAAA", ttl: 300, data: ip });
          }
        }
        if (rrList.length === 0 && ipList.length > 0) {
          const first = ipList[0];
          const t = first.includes(":") ? "AAAA" : "A";
          rrList.push({ name: lowerName, type: t, ttl: 300, data: first });
        }

        const respBuf = buildDnsAnswerPacket(qBuf, rrList);

        // Forward to upstream DOH (wire) and await it
        try {
          const upstreamRes = await forwardToUpstreamWire(qBuf);
          console.log(`Forwarded ${lowerName} (override) to upstream (wire) status=${upstreamRes.status}`);
        } catch (e) {
          console.error("Upstream forward (wire) failed:", e.message);
        }

        return sendWireResponse(res, respBuf);
      } else {
        // Not in hosts - forward to upstream
        const upstreamRes = await forwardToUpstreamWire(qBuf);
        if (upstreamRes.headers["content-type"]) res.setHeader("content-type", upstreamRes.headers["content-type"]);
        if (upstreamRes.headers["content-encoding"]) res.setHeader("content-encoding", upstreamRes.headers["content-encoding"]);
        if (upstreamRes.headers["cache-control"]) res.setHeader("cache-control", upstreamRes.headers["cache-control"]);
        res.status(upstreamRes.status).send(upstreamRes.buffer);
        return;
      }
    } else if (wantsJson) {
      // DNS-JSON style (GET or POST)
      const name = (req.query.name || (req.body && req.body.name) || "").toString();
      const type = (req.query.type || (req.body && req.body.type) || "A").toString().toUpperCase();

      if (!name) {
        res.status(400).json({ Status: 1, Comment: "missing name parameter" });
        return;
      }

      const lowerName = name.replace(/\.$/, "").toLowerCase();
      if (hosts.has(lowerName)) {
        const ipList = hosts.get(lowerName);
        const answers = [];
        for (const ip of ipList) {
          if ((type === "A" && ip.includes(".")) || type === "ANY") answers.push({ name: lowerName, type: 1, TTL: 300, data: ip });
          else if ((type === "AAAA" && ip.includes(":")) || type === "ANY") answers.push({ name: lowerName, type: 28, TTL: 300, data: ip });
        }
        if (answers.length === 0 && ipList.length > 0) {
          const first = ipList[0];
          const t = first.includes(":") ? 28 : 1;
          answers.push({ name: lowerName, type: t, TTL: 300, data: first });
        }

        // Forward to upstream dns-json and await
        try {
          const upstreamRes = await forwardToUpstreamJson(name, type);
          console.log(`Forwarded ${name} (override) to upstream (dns-json) status=${upstreamRes.status}`);
        } catch (e) {
          console.error("Forward to upstream dns-json failed:", e.message);
        }

        res.json({ Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: lowerName, type }], Answer: answers });
        return;
      } else {
        // Forward to upstream dns-json
        try {
          const upstreamRes = await forwardToUpstreamJson(name, type);
          if (upstreamRes.json) {
            res.setHeader("content-type", "application/dns-json; charset=utf-8");
            res.status(upstreamRes.status).json(upstreamRes.json);
          } else {
            res.status(502).json({ Status: 2, Comment: "upstream returned non-json" });
          }
        } catch (e) {
          res.status(502).json({ Status: 2, Comment: "upstream failure", error: e.message });
        }
        return;
      }
    } else {
      // Unknown request type - proxy to upstream as-is (try to preserve body and headers)
      const body = req.rawBody && req.rawBody.length ? req.rawBody : undefined;
      // Clone headers, but strip hop-by-hop stuff and host
      const headers = { ...req.headers };
      delete headers.host;
      try {
        const upstreamRes = await fetch(UPSTREAM, { method: req.method, headers, body, redirect: "follow" });
        const buf = Buffer.from(await upstreamRes.arrayBuffer());
        if (upstreamRes.headers.get("content-type")) res.setHeader("content-type", upstreamRes.headers.get("content-type"));
        if (upstreamRes.headers.get("content-encoding")) res.setHeader("content-encoding", upstreamRes.headers.get("content-encoding"));
        res.status(upstreamRes.status).send(buf);
      } catch (e) {
        res.status(502).send("Upstream DOH proxy error: " + e.message);
      }
    }
  } catch (err) {
    console.error("Handler error:", err);
    res.status(500).send("Internal server error: " + err.message);
  }
});

const server = http.createServer(app);
server.listen(PORT, () => {
  console.log(`DOH proxy listening on http://0.0.0.0:${PORT}`);
  console.log(`Upstream DOH: ${UPSTREAM}`);
  console.log(`Hosts file: ${HOSTS_FILE}`);
});

