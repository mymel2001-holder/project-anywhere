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

const PORT = Number(process.env.PORT || 8053);
const UPSTREAM = process.env.UPSTREAM_DOH || "https://one.one.one.one/dns-query";
const HOSTS_FILE = process.env.HOSTS_FILE || "./hosts.json";
// PROXY_HOST should ideally be an IP, but we will resolve it if it's a hostname
const PROXY_HOST_INPUT = process.env.PROXY_HOST || "anywhere.nodemixaholic.com";
const IGNORE_TLS = (process.env.IGNORE_TLS || "true").toLowerCase() === "true";

let PROXY_IP = null;

// Resolve PROXY_HOST to an IP on startup
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
      console.error(`Failed to resolve PROXY_HOST: ${e.message}`);
      process.exit(1);
    }
  }
}

// hostname -> [targets]
let hosts = loadHosts();

// Load hosts.json
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

// Detect private IP
function isPrivateIp(ip) {
  if (!ip) return false;
  const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a,b] = [Number(v4[1]), Number(v4[2])];
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127;
  }
  const lower = ip.toLowerCase();
  return lower === "::1" || lower.startsWith("fe80:") || /^f[cd]/.test(lower);
}

// Resolve hostnames in hosts.json entries to IPs
async function resolveHostsEntry(entry) {
  const resolved = [];
  for (const t of entry) {
    if (isPrivateIp(t) || t.match(/^\d+(\.\d+){3}$/) || t.includes(":")) {
      resolved.push(t);
    } else {
      resolved.push(t); // Keep as-is for public hostname
    }
  }
  return resolved;
}

// Forward DNS wire to upstream
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

// Build DNS packet
function buildDnsAnswerPacket(queryBuffer, rrList) {
  const q = dnsPacket.decode(queryBuffer);
  return dnsPacket.encode({
    id: q.id,
    type: "response",
    flags: q.flags,
    questions: q.questions,
    answers: rrList.map(r => ({ name: r.name, type: r.type, ttl: r.ttl || 300, class:"IN", data: r.data }))
  });
}

// Extract first question
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

// --- FIXED REVERSE PROXY MIDDLEWARE ---
app.use(async (req, res, next) => {
  try {
    const hostHeader = (req.headers.host || "").split(":")[0].toLowerCase();
    
    // Check hosts map directly instead of relying on ephemeral 'mapping' cache
    if (!hosts.has(hostHeader)) return next();

    const targets = await resolveHostsEntry(hosts.get(hostHeader));
    const localTarget = targets.find(isPrivateIp);

    // If no local target found in hosts.json, skip proxying
    if (!localTarget) return next();

    // Default to HTTP for internal IPs to avoid SSL mismatch errors
    // Use the incoming URL path and query
    const protocol = "http"; 
    const url = `${protocol}://${localTarget}${req.originalUrl || req.url}`;
    
    // Pass original headers, but update Host to match logic if needed (usually keep original)
    const headers = { ...req.headers };

    // Prepare fetch options
    const options = {
      method: req.method,
      headers: headers,
      agent: protocol === "https" ? new https.Agent({ rejectUnauthorized: !IGNORE_TLS }) : undefined
    };

    // Only attach body for methods that support it (prevents GET hangs)
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      options.body = req.rawBody;
    }

    let upstreamRes;
    try {
      upstreamRes = await fetch(url, options);
    } catch (err) {
      console.error(`Proxy fetch failed for ${url}:`, err.message);
      return res.status(502).send("Bad Gateway - Proxy Connection Failed");
    }

    // Forward headers
    upstreamRes.headers.forEach((v, k) => {
      if (!["connection", "keep-alive", "transfer-encoding", "upgrade", "content-length"].includes(k)) {
        res.setHeader(k, v);
      }
    });

    res.status(upstreamRes.status);
    
    // Pipe response
    const arrayBuf = await upstreamRes.arrayBuffer();
    res.send(Buffer.from(arrayBuf));

  } catch (e) {
    console.error("Proxy error:", e);
    res.status(500).send("Internal Proxy Error");
  }
});


// Send wire response helper
function sendWire(res, buf){
  res.setHeader("content-type","application/dns-message");
  res.setHeader("content-length", buf.length);
  res.status(200).send(buf);
}

// DoH handler
app.all(/.*/, async (req,res)=>{
  try {
    const accept = (req.headers.accept||"").toLowerCase();
    const wantsJson = accept.includes("application/dns-json") || req.query.name;

    // DNS wire GET
    if(req.method==="GET" && req.query.dns){
      const dnsBuf = Buffer.from(req.query.dns.replace(/-/g,"+").replace(/_/g,"/")+"==","base64");
      const qinfo = questionNameAndType(dnsBuf);
      const name = qinfo?.name.toLowerCase();
      
      if(name && hosts.has(name)){
        const resolvedTargets = await resolveHostsEntry(hosts.get(name));
        const localTargets = resolvedTargets.filter(isPrivateIp);
        const publicTargets = resolvedTargets.filter(ip => !isPrivateIp(ip));

        if(localTargets.length && PROXY_IP){
          // Return the PROXY_IP (this server), not the string hostname
          const rr = [{ name, type: "A", data: PROXY_IP }];
          forwardToUpstreamWire(dnsBuf).catch(()=>{});
          return sendWire(res, buildDnsAnswerPacket(dnsBuf, rr));
        }

        if(publicTargets.length){
          const rr = publicTargets.map(ip=>({ name, type: ip.includes(":")?"AAAA":"A", data: ip }));
          forwardToUpstreamWire(dnsBuf).catch(()=>{});
          return sendWire(res, buildDnsAnswerPacket(dnsBuf, rr));
        }
      }

      const upstreamRes = await forwardToUpstreamWire(dnsBuf);
      res.set(upstreamRes.headers);
      return res.status(upstreamRes.status).send(upstreamRes.buffer);
    }

    // DNS wire POST
    if(req.method==="POST" && (req.headers["content-type"]||"").includes("application/dns-message")){
      const dnsBuf = req.rawBody || Buffer.alloc(0);
      const qinfo = questionNameAndType(dnsBuf);
      const name = qinfo?.name.toLowerCase();
      
      if(name && hosts.has(name)){
        const resolvedTargets = await resolveHostsEntry(hosts.get(name));
        const localTargets = resolvedTargets.filter(isPrivateIp);
        const publicTargets = resolvedTargets.filter(ip => !isPrivateIp(ip));

        if(localTargets.length && PROXY_IP){
           // Return the PROXY_IP (this server)
          const rr = [{ name, type: "A", data: PROXY_IP }];
          forwardToUpstreamWire(dnsBuf).catch(()=>{});
          return sendWire(res, buildDnsAnswerPacket(dnsBuf, rr));
        }

        if(publicTargets.length){
          const rr = publicTargets.map(ip=>({ name, type: ip.includes(":")?"AAAA":"A", data: ip }));
          forwardToUpstreamWire(dnsBuf).catch(()=>{});
          return sendWire(res, buildDnsAnswerPacket(dnsBuf, rr));
        }
      }

      const upstreamRes = await forwardToUpstreamWire(dnsBuf);
      res.set(upstreamRes.headers);
      return res.status(upstreamRes.status).send(upstreamRes.buffer);
    }

    // DNS JSON
    if(wantsJson){
      const name = (req.query.name||req.body?.name||"").toString();
      const type = (req.query.type||req.body?.type||"A").toString().toUpperCase();
      if(!name) return res.status(400).json({ Status:1, Comment:"missing name" });

      const lower = name.toLowerCase();
      if(hosts.has(lower)){
        const resolvedTargets = await resolveHostsEntry(hosts.get(lower));
        const localTargets = resolvedTargets.filter(isPrivateIp);
        const publicTargets = resolvedTargets.filter(ip => !isPrivateIp(ip));

        if(localTargets.length && PROXY_IP){
          return res.json({ Status:0, Answer: [ { name:lower, type:1, TTL:300, data:PROXY_IP } ] });
        }

        if(publicTargets.length){
          return res.json({ Status:0, Answer: publicTargets.map(ip=>({ name:lower, type:1, TTL:300, data:ip })) });
        }
      }

      const r = await fetch(`${UPSTREAM}?name=${name}&type=${type}`,{ headers:{ Accept:"application/dns-json" } });
      const j = await r.json().catch(()=>null);
      if(j) return res.status(r.status).json(j);
      return res.status(502).json({ Status:2, Comment:"upstream failed" });
    }

    return res.status(404).send("Not Found");
  } catch(e){ console.error(e); return res.status(500).send("Internal error"); }
});

// Initialize IP then start server
initProxyIp().then(() => {
  http.createServer(app).listen(PORT,()=>{
    console.log(`DOH + Reverse Proxy listening on http://0.0.0.0:${PORT}`);
    console.log(`Upstream DOH: ${UPSTREAM}`);
    console.log(`Hosts file: ${HOSTS_FILE}`);
    console.log(`Proxy IP (resolved): ${PROXY_IP}`);
  });
});
