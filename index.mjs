// doh-proxy.js
// Node.js DOH proxy that supports hosts.json override and upstream DOH forwarding.
// Usage: node doh-proxy.js
// Config via environment variables:
//   UPSTREAM_DOH (default: https://one.one.one.one/dns-query)
//   HOSTS_FILE  (default: ./hosts.json)
//   PORT        (default: 8053)

import fs from "fs";
import http from "http";
import https from "https";
import express from "express";
import fetch from "node-fetch";
import dnsPacket from "dns-packet";
import zlib from "zlib";
import { URL } from "url";

const PORT = process.env.PORT ? Number(process.env.PORT) : 8053;
const UPSTREAM = process.env.UPSTREAM_DOH || "https://one.one.one.one/dns-query";
const HOSTS_FILE = process.env.HOSTS_FILE || "./hosts.json";

function loadHosts() {
  try {
    const raw = fs.readFileSync(HOSTS_FILE, "utf8");
    const json = JSON.parse(raw);
    // normalize to map of lower-case name -> array of ips
    const map = new Map();
    for (const [k, v] of Object.entries(json)) {
      const key = k.toLowerCase().replace(/\.$/, ""); // strip trailing dot if any
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
// Optional: watch file and reload on change
fs.watchFile(HOSTS_FILE, { interval: 1000 }, () => {
  console.log("Hosts file changed, reloading...");
  hosts = loadHosts();
});

function isPrivateIp(ip) {
  // approximate checks for IPv4 and IPv6 private ranges and loopback
  if (!ip || typeof ip !== "string") return false;
  // IPv4
  const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const a = +v4[1], b = +v4[2];
    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12 => 172.16-31.x.x
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 127.0.0.0/8 loopback
    if (a === 127) return true;
    return false;
  }
  // IPv6 shorthand checks
  const ipLower = ip.toLowerCase();
  // loopback ::1
  if (ipLower === "::1") return true;
  // Unique local addresses fc00::/7 (fd00::/8 commonly)
  if (/^f[cd]/.test(ipLower)) return true;
  // link-local fe80::
  if (ipLower.startsWith("fe80:")) return true;
  return false;
}

async function forwardToUpstreamWire(dnsWireBuffer, upstream = UPSTREAM, method = "POST", accept = "application/dns-message") {
  // Forward raw wire-format DNS to upstream DOH. Returns response buffer and headers.
  const headers = {
    "content-type": "application/dns-message",
    Accept: accept,
    "user-agent": "doh-proxy/1.0"
  };

  // Some DOH servers accept GET?dns=base64url; but we'll use POST for binary
  const res = await fetch(upstream, {
    method,
    headers,
    body: dnsWireBuffer,
    // follow redirects
    redirect: "follow",
  });

  const respHeaders = {};
  res.headers.forEach((v, k) => (respHeaders[k] = v));
  const arrayBuffer = await res.arrayBuffer();
  return { buffer: Buffer.from(arrayBuffer), status: res.status, headers: respHeaders };
}

async function forwardToUpstreamJson(name, type = "A", upstream = UPSTREAM) {
  // forwards using application/dns-json (GET)
  const u = new URL(upstream);
  // If upstream recognizes dns-json?name=..&type=.. then use that, else fallback to wire
  // We'll attempt GET with ?name=...&type=...
  u.searchParams.set("name", name);
  u.searchParams.set("type", type);
  const res = await fetch(String(u), { headers: { Accept: "application/dns-json", "user-agent": "doh-proxy/1.0" } });
  const json = await res.json();
  return { json, status: res.status, headers: Object.fromEntries(res.headers) };
}

function buildDnsAnswerPacket(queryPacketBuffer, rrList) {
  // rrList: array of objects { name, type: 'A'|'AAAA'|'CNAME'..., ttl, data }
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
    // dns-packet expects type to be numeric or string; data for A is dotted IP, AAAA is IPv6 string
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

// express raw body for binary content-types
app.use((req, res, next) => {
  // capture raw body for application/dns-message or other binary
  const contentType = req.headers["content-type"] || "";
  if (req.method === "POST" && contentType.indexOf("application/dns-message") !== -1) {
    // collect raw bytes
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      req.rawBody = Buffer.concat(chunks);
      next();
    });
    req.on("error", next);
  } else {
    // buffer for other requests as well
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      req.rawBody = Buffer.concat(chunks);
      next();
    });
    req.on("error", next);
  }
});

// Helper to respond with wire format
function sendWireResponse(res, buffer) {
  // Allow callers to compress or not depending on Accept-Encoding; but DOH normally expects uncompressed DNS messages.
  res.setHeader("content-type", "application/dns-message");
  res.setHeader("content-length", buffer.length);
  res.status(200).send(buffer);
}

// Main route accepts any path (some DOH clients call /dns-query, some root)
app.all("/*", async (req, res) => {
  try {
    // Determine mode: wire vs json
    const accept = (req.headers.accept || "").toLowerCase();
    const wantsJson = accept.includes("application/dns-json") || req.query.name !== undefined || req.query.type !== undefined;
    // Wire format handling:
    // GET?dns=base64url OR POST with application/dns-message
    if (req.method === "GET" && req.query.dns) {
      // GET wire format: dns param is base64url
      const dnsParam = req.query.dns;
      // base64url -> buffer
      const b64 = dnsParam.replace(/-/g, "+").replace(/_/g, "/");
      const pad = b64.length % 4;
      const padded = b64 + (pad ? "=".repeat(4 - pad) : "");
      const qBuf = Buffer.from(padded, "base64");

      const qinfo = questionNameAndTypeFromWire(qBuf);
      const lowerName = qinfo ? qinfo.name.toLowerCase() : null;

      if (lowerName && hosts.has(lowerName)) {
        // host override
        const ipList = hosts.get(lowerName);
        // choose first matching type: if question is AAAA try IPv6, else IPv4
        let rrList = [];
        const qType = qinfo.type || "A";
        for (const ip of ipList) {
          if (qType === "A" && ip.includes(".")) {
            rrList.push({ name: lowerName, type: "A", ttl: 300, data: ip });
          } else if (qType === "AAAA" && ip.includes(":")) {
            rrList.push({ name: lowerName, type: "AAAA", ttl: 300, data: ip });
          } else if (qType === "ANY") {
            // include all
            if (ip.includes(".")) rrList.push({ name: lowerName, type: "A", ttl: 300, data: ip });
            if (ip.includes(":")) rrList.push({ name: lowerName, type: "AAAA", ttl: 300, data: ip });
          }
        }
        // If we didn't get rrList entries matching the requested type, still try to reply with first IP as A or AAAA
        if (rrList.length === 0 && ipList.length > 0) {
          const first = ipList[0];
          const t = first.includes(":") ? "AAAA" : "A";
          rrList.push({ name: lowerName, type: t, ttl: 300, data: first });
        }

        // Build response packet
        const respBuf = buildDnsAnswerPacket(qBuf, rrList);

        // Fire-and-forget forward to upstream (so upstream sees queries), but do not wait for it before responding.
        // We'll still try to forward but don't block client's response on it.
        forwardToUpstreamWire(qBuf).catch((e) => console.error("Upstream forward failed:", e.message));

        return sendWireResponse(res, respBuf);
      } else {
        // not in hosts -> proxy to upstream DOH (binary)
        const upstreamRes = await forwardToUpstreamWire(qBuf);
        // Respond with exact binary bytes, and pass through content-type
        res.setHeader("content-type", upstreamRes.headers["content-type"] || "application/dns-message");
        // pass cache-control etc if present
        if (upstreamRes.headers["cache-control"]) res.setHeader("cache-control", upstreamRes.headers["cache-control"]);
        if (upstreamRes.headers["content-encoding"]) res.setHeader("content-encoding", upstreamRes.headers["content-encoding"]);
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
        forwardToUpstreamWire(qBuf).catch((e) => console.error("Upstream forward failed:", e.message));
        return sendWireResponse(res, respBuf);
      } else {
        // not in hosts -> forward to upstream
        const upstreamRes = await forwardToUpstreamWire(qBuf);
        // pass through headers (content-type, encoding)
        if (upstreamRes.headers["content-type"]) res.setHeader("content-type", upstreamRes.headers["content-type"]);
        if (upstreamRes.headers["content-encoding"]) res.setHeader("content-encoding", upstreamRes.headers["content-encoding"]);
        if (upstreamRes.headers["cache-control"]) res.setHeader("cache-control", upstreamRes.headers["cache-control"]);
        res.status(upstreamRes.status).send(upstreamRes.buffer);
        return;
      }
    } else if (wantsJson) {
      // application/dns-json style (GET or POST) using name & type
      const name = (req.query.name || (req.body && req.body.name) || "").toString();
      const type = (req.query.type || (req.body && req.body.type) || "A").toString().toUpperCase();

      if (!name) {
        res.status(400).json({ Status: 1, Comment: "missing name parameter" });
        return;
      }

      const lowerName = name.replace(/\.$/, "").toLowerCase();
      if (hosts.has(lowerName)) {
        // Return JSON format answer with IP(s)
        const ipList = hosts.get(lowerName);
        const answers = [];
        for (const ip of ipList) {
          if ((type === "A" && ip.includes(".")) || type === "ANY") {
            answers.push({ name: lowerName, type: 1, TTL: 300, data: ip }); // type 1 = A
          } else if ((type === "AAAA" && ip.includes(":")) || type === "ANY") {
            answers.push({ name: lowerName, type: 28, TTL: 300, data: ip }); // type 28 = AAAA
          }
        }
        if (answers.length === 0 && ipList.length > 0) {
          const first = ipList[0];
          const t = first.includes(":") ? 28 : 1;
          answers.push({ name: lowerName, type: t, TTL: 300, data: first });
        }

        // Fire-and-forget forward to upstream in background (do not wait)
        forwardToUpstreamJson(name, type).catch((e) => console.error("Forward to upstream dns-json failed:", e.message));

        res.json({ Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: lowerName, type }], Answer: answers });
        return;
      } else {
        // forward to upstream dns-json
        try {
          const upstreamRes = await forwardToUpstreamJson(name, type);
          // assume upstream returned JSON
          res.setHeader("content-type", "application/dns-json; charset=utf-8");
          res.status(upstreamRes.status).json(upstreamRes.json);
        } catch (e) {
          res.status(502).json({ Status: 2, Comment: "upstream failure", error: e.message });
        }
        return;
      }
    } else {
      // Unknown/unsupported request type: attempt to proxy to upstream as-is
      // If there is a rawBody, forward using same content-type
      const body = req.rawBody && req.rawBody.length ? req.rawBody : undefined;
      const headers = { ...req.headers };
      // remove hop-by-hop headers
      delete headers.host;
      try {
        const upstreamRes = await fetch(UPSTREAM, { method: req.method, headers, body, redirect: "follow" });
        const buf = Buffer.from(await upstreamRes.arrayBuffer());
        // copy selected headers
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

// Start server
const server = http.createServer(app);
server.listen(PORT, () => {
  console.log(`DOH proxy listening on http://0.0.0.0:${PORT}`);
  console.log(`Upstream DOH: ${UPSTREAM}`);
  console.log(`Hosts file: ${HOSTS_FILE}`);
});

