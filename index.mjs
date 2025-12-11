// doh-reverse-fixed.mjs
import fs from "fs";
import http from "http";
import https from "https";
import express from "express";
import fetch from "node-fetch";
import dnsPacket from "dns-packet";
import dns from "dns";
import { promisify } from "util";

const dnsLookup = promisify(dns.lookup);

// CONFIGURATION
const PORT = Number(process.env.PORT || 8053);
const UPSTREAM = process.env.UPSTREAM_DOH || "https://one.one.one.one/dns-query";
const HOSTS_FILE = process.env.HOSTS_FILE || "./hosts.json";
// This MUST be the Public IP or Hostname of THIS Node server.
// If it's a Hostname, we resolve it to an IP on startup.
const PROXY_HOST_INPUT = process.env.PROXY_HOST || "anywhere.nodemixaholic.com";
const IGNORE_TLS = (process.env.IGNORE_TLS || "true").toLowerCase() === "true";

let PROXY_IP = null; // The actual IP we send to clients

// 1. Resolve our own Public IP on startup
// We need this because DNS A-Records MUST contain an IP, not a hostname string.
async function initProxyIp() {
  if (isPrivateIp(PROXY_HOST_INPUT) || PROXY_HOST_INPUT.match(/^\d+(\.\d+){3}$/)) {
    PROXY_IP = PROXY_HOST_INPUT;
  } else {
    try {
      console.log(`Resolving PROXY_HOST (${PROXY_HOST_INPUT})...`);
      const { address } = await dnsLookup(PROXY_HOST_INPUT);
      PROXY_IP = address;
      console.log(`Resolved PROXY_HOST to: ${PROXY_IP}`);
    } catch (e) {
      console.error(`CRITICAL: Failed to resolve PROXY_HOST. Clients won't reach me. Error: ${e.message}`);
      process.exit(1);
    }
  }
}

// 2. Load hosts.json
let hosts = loadHosts();

function loadHosts() {
  try {
    if (!fs.existsSync(HOSTS_FILE)) return new Map();
    const data = fs.readFileSync(HOSTS_FILE, "utf8");
    const json = JSON.parse(data);
    const map = new Map();
    for (const [host, targets] of Object.entries(json)) {
      map.set(host.toLowerCase().replace(/\.$/, ""), Array.isArray(targets) ? targets : [String(targets)]);
    }
    return map;
  } catch (e) {
    console.warn("Failed to load hosts.json:", e.message);
    return new Map();
  }
}

fs.watchFile(HOSTS_FILE, { interval: 1000 }, () => {
  console.log("Hosts file changed, reloading...");
  hosts = loadHosts();
});

function isPrivateIp(ip) {
  if (!ip) return false;
  const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a,b] = [Number(v4[1]), Number(v4[2])];
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127;
  }
  return false;
}

// Helper: Resolve entry (handles list of IPs)
async function resolveHostsEntry(entry) {
  return entry; // In your case, hosts.json already contains IPs
}

// Helper: Forward DNS to Cloudflare
async function forwardToUpstreamWire(buf) {
  const res = await fetch(UPSTREAM, {
    method: "POST",
    headers: { "Content-Type":"application/dns-message", "Accept":"application/dns-message" },
    body: buf
  });
  const arrayBuffer = await res.arrayBuffer();
  const headers = {};
  res.headers.forEach((v,k)=>headers[k]=v);
  return { buffer: Buffer.from(arrayBuffer), headers, status: res.status };
}

// Helper: Build DNS Packet
function buildDnsAnswerPacket(queryBuffer, rrList) {
  const q = dnsPacket.decode(queryBuffer);
  return dnsPacket.encode({
    id: q.id,
    type: "response",
    flags: q.flags,
    questions: q.questions,
    answers: rrList.map(r => ({ name: r.name, type: r.type, ttl: 60, class:"IN", data: r.data }))
  });
}

function questionNameAndType(buf) {
  try {
    const p = dnsPacket.decode(buf);
    if (!p.questions || !p.questions.length) return null;
    const q = p.questions[0];
    return { name: q.name.replace(/\.$/,""), type: q.type || "A" };
  } catch { return null; }
}

const app = express();

// Raw body parser
app.use((req,res,next)=>{
  const chunks = [];
  req.on("data", c=>chunks.push(c));
  req.on("end", ()=>{ req.rawBody = Buffer.concat(chunks); next(); });
  req.on("error", next);
});

// ==========================================
//  THE FIX: Stateless Reverse Proxy Logic
// ==========================================
app.use(async (req, res, next) => {
  // 1. Identify the requested Host (e.g., samantha.femboy)
  const hostHeader = (req.headers.host || "").split(":")[0].toLowerCase();

  // 2. Check hosts.json directly. NO cached 'mapping' check.
  if (!hosts.has(hostHeader)) {
    return next(); // Not in our list? Pass to DoH handler.
  }

  // 3. Determine the internal destination IP
  const targets = hosts.get(hostHeader);
  const internalIp = targets.find(t => isPrivateIp(t) || t.includes(":"));

  if (!internalIp) return next(); // No internal IP found? Pass.

  // 4. Proxy the request
  try {
    // Force HTTP for internal services (avoids self-signed cert issues internally)
    const targetUrl = `http://${internalIp}${req.originalUrl || req.url}`;
    
    // console.log(`Proxying ${hostHeader} -> ${targetUrl}`); // Uncomment for debug

    const fetchOptions = {
      method: req.method,
      headers: { ...req.headers, host: hostHeader }, // Preserve original Host header!
      redirect: 'manual'
    };

    // Only attach body for methods that allow it
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      fetchOptions.body = req.rawBody;
    }

    const upstreamRes = await fetch(targetUrl, fetchOptions);

    // Forward headers back to client
    upstreamRes.headers.forEach((v, k) => {
      // filtering hop-by-hop headers
      if (!["content-length", "connection", "keep-alive"].includes(k)) {
        res.setHeader(k, v);
      }
    });

    res.status(upstreamRes.status);
    
    // Stream response body
    const arrayBuf = await upstreamRes.arrayBuffer();
    res.send(Buffer.from(arrayBuf));

  } catch (e) {
    console.error(`Proxy Error connecting to ${internalIp}:`, e.message);
    res.status(502).send("Bad Gateway - Proxy Failed");
  }
});

// Helper: Send DNS Wire Response
function sendWire(res, buf){
  res.setHeader("content-type","application/dns-message");
  res.setHeader("content-length", buf.length);
  res.status(200).send(buf);
}

// ==========================================
//  DoH Handler (DNS Logic)
// ==========================================
app.all(/.*/, async (req,res)=>{
  try {
    const accept = (req.headers.accept||"").toLowerCase();
    const wantsJson = accept.includes("application/dns-json") || req.query.name;

    // --- DNS WIRE FORMAT ---
    if((req.method==="GET" && req.query.dns) || (req.method==="POST" && req.headers["content-type"]==="application/dns-message")){
      const dnsBuf = req.method==="GET" 
        ? Buffer.from(req.query.dns.replace(/-/g,"+").replace(/_/g,"/")+"==","base64")
        : (req.rawBody || Buffer.alloc(0));
      
      const qinfo = questionNameAndType(dnsBuf);
      const name = qinfo?.name.toLowerCase();

      // IF domain is in hosts.json, intercept it!
      if(name && hosts.has(name) && PROXY_IP) {
        // Return OUR Public IP, not the internal 192.168...
        const rr = [{ name, type: "A", data: PROXY_IP }];
        return sendWire(res, buildDnsAnswerPacket(dnsBuf, rr));
      }

      // ELSE forward to Cloudflare
      const upstreamRes = await forwardToUpstreamWire(dnsBuf);
      res.set(upstreamRes.headers);
      return res.status(upstreamRes.status).send(upstreamRes.buffer);
    }

    // --- DNS JSON FORMAT (Chrome/etc sometimes use this) ---
    if(wantsJson){
      const name = (req.query.name||req.body?.name||"").toString().toLowerCase();
      const type = (req.query.type||req.body?.type||"A").toString().toUpperCase();

      if(name && hosts.has(name) && PROXY_IP) {
        return res.json({ Status:0, Answer: [ { name, type:1, TTL:60, data:PROXY_IP } ] });
      }

      const r = await fetch(`${UPSTREAM}?name=${name}&type=${type}`,{ headers:{ Accept:"application/dns-json" } });
      const j = await r.json().catch(()=>null);
      if(j) return res.status(r.status).json(j);
      return res.status(502).json({ Status:2, Comment:"upstream failed" });
    }

    return res.status(404).send("Not Found");
  } catch(e){ console.error(e); return res.status(500).send("Internal error"); }
});

// Start Server
initProxyIp().then(() => {
  http.createServer(app).listen(PORT, "0.0.0.0", () => {
    console.log(`DoH+Proxy running on port ${PORT}`);
    console.log(`Public Proxy IP (returned to clients): ${PROXY_IP}`);
    console.log(`Hosts file loaded: ${hosts.size} entries.`);
  });
});
