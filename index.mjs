// doh-reverse-final.mjs

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
// PROXY_HOST_INPUT is the hostname exposed by the Cloudflare Tunnel 
const PROXY_HOST_INPUT = process.env.PROXY_HOST || "anywhere.nodemixaholic.com"; 

let hosts = loadHosts();
let PROXY_IP_FOR_PUBLIC_A_RECORDS = null; 

// --- Setup Functions (No changes needed here from last version) ---

async function initProxyConfig() {
  if (isPrivateIp(PROXY_HOST_INPUT) || PROXY_HOST_INPUT.match(/^\d+(\.\d+){3}$/)) {
    PROXY_IP_FOR_PUBLIC_A_RECORDS = PROXY_HOST_INPUT;
  } else {
    try {
      console.log(`Resolving PROXY_HOST (${PROXY_HOST_INPUT}) to get an IP for optional A records...`);
      const { address } = await dnsLookup(PROXY_HOST_INPUT);
      PROXY_IP_FOR_PUBLIC_A_RECORDS = address;
      console.log(`Resolved PROXY_HOST for A-records: ${PROXY_IP_FOR_PUBLIC_A_RECORDS}`);
    } catch (e) {
      console.warn(`Could not resolve PROXY_HOST, falling back to CNAME only for local targets.`);
    }
  }
}

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

function forwardToUpstreamWire(buf) {
  const res = fetch(UPSTREAM, {
    method: "POST",
    headers: { "Content-Type":"application/dns-message", "Accept":"application/dns-message" },
    body: buf
  });
  return res.then(r => r.arrayBuffer().then(arrayBuffer => ({
    buffer: Buffer.from(arrayBuffer),
    headers: Object.fromEntries(r.headers.entries()),
    status: r.status
  })));
}

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
//  *** REWRITTEN: Stateless Reverse Proxy Middleware ***
// ==========================================
app.use(async (req, res, next) => {
  const hostHeader = (req.headers.host || "").split(":")[0].toLowerCase();

  if (!hosts.has(hostHeader)) {
    return next(); 
  }

  const targets = hosts.get(hostHeader);
  const internalTarget = targets.find(t => isPrivateIp(t) || t.includes(":")); 

  if (!internalTarget) return next();

  // Determine the internal URL and the Host header to use internally
  const [internalIp, internalPort] = internalTarget.split(':');
  
  // Use the internal IP/Port in the URL
  const targetUrl = `http://${internalTarget}${req.originalUrl || req.url}`;
  
  // *** CRITICAL FIX: Use the actual IP/Port as the internal Host header ***
  // This is required because the internal service (e.g., Nginx, Apache) 
  // at 192.168.50.238 may not recognize 'samantha.femboy'.
  const internalHostHeader = internalTarget; 
  
  try {
    const fetchOptions = {
      method: req.method,
      // Overwrite the Host header for the internal request with the IP/Port
      headers: { ...req.headers, host: internalHostHeader }, 
      redirect: 'manual',
      agent: new http.Agent({ rejectUnauthorized: false })
    };

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      fetchOptions.body = req.rawBody;
    }

    const upstreamRes = await fetch(targetUrl, fetchOptions);

    // Forward headers back to the client
    upstreamRes.headers.forEach((v, k) => {
      if (!["content-length", "connection", "keep-alive"].includes(k)) {
        res.setHeader(k, v);
      }
    });

    res.status(upstreamRes.status);
    
    const arrayBuf = await upstreamRes.arrayBuffer();
    res.send(Buffer.from(arrayBuf));

  } catch (e) {
    console.error(`Proxy Error connecting to ${internalTarget}:`, e.message);
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
//  DoH Handler (No changes needed here)
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

      if(name && hosts.has(name)) {
        const resolvedTargets = hosts.get(name);
        const localTargets = resolvedTargets.filter(isPrivateIp);
        const publicTargets = resolvedTargets.filter(ip => !isPrivateIp(ip));

        if(localTargets.length){
          // Return CNAME (Type 5) pointing to the tunnel hostname (PROXY_HOST_INPUT)
          const rr = [{ name, type: 5, data: PROXY_HOST_INPUT }];
          return sendWire(res, buildDnsAnswerPacket(dnsBuf, rr));
        }

        if(publicTargets.length && PROXY_IP_FOR_PUBLIC_A_RECORDS){
          const rr = publicTargets.map(ip=>({ name, type: ip.includes(":")?"AAAA":"A", data: ip }));
          return sendWire(res, buildDnsAnswerPacket(dnsBuf, rr));
        }
      }

      const upstreamRes = await forwardToUpstreamWire(dnsBuf);
      res.set(upstreamRes.headers);
      return res.status(upstreamRes.status).send(upstreamRes.buffer);
    }

    // --- DNS JSON FORMAT ---
    if(wantsJson){
      const name = (req.query.name||req.body?.name||"").toString().toLowerCase();
      const type = (req.query.type||req.body?.type||"A").toString().toUpperCase();

      if(name && hosts.has(name)) {
        const resolvedTargets = hosts.get(name);
        const localTargets = resolvedTargets.filter(isPrivateIp);
        const publicTargets = resolvedTargets.filter(ip => !isPrivateIp(ip));
        
        if(localTargets.length) {
          // Return CNAME (Type 5) pointing to the tunnel hostname (PROXY_HOST_INPUT)
          return res.json({ 
            Status:0, 
            Answer: [ 
              { name, type: 5, TTL: 60, data: PROXY_HOST_INPUT } 
            ] 
          });
        }
        
        if(publicTargets.length) {
           return res.json({ Status:0, Answer: publicTargets.map(ip=>({ name, type: ip.includes(":")?28:1, TTL:60, data:ip })) });
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

// Start Server
initProxyConfig().then(() => {
  http.createServer(app).listen(PORT, "0.0.0.0", () => {
    console.log(`DoH+Proxy running on port ${PORT}`);
    console.log(`CNAME target for local hosts: ${PROXY_HOST_INPUT}`);
    console.log(`Hosts file loaded: ${hosts.size} entries.`);
  });
});
