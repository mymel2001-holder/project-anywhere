// server.mjs
import fs from "fs";
import http from "http";
import express from "express";
import fetch from "node-fetch";
import dnsPacket from "dns-packet";
import dns from "dns";
import { promisify } from "util";

const dnsLookup = promisify(dns.lookup);
const app = express();

// --- CONFIGURATION ---
const PORT = Number(process.env.PORT || 8053);
const UPSTREAM_DOH = process.env.UPSTREAM_DOH || "https://one.one.one.one/dns-query";
const HOSTS_FILE = process.env.HOSTS_FILE || "./hosts.json";

// PROXY_PUBLIC_HOST is the hostname exposed by the Cloudflare Tunnel 
// (e.g., anywhere.nodemixaholic.com). This is the CNAME target.
const PROXY_PUBLIC_HOST = process.env.PROXY_HOST || "anywhere.nodemixaholic.com"; 

let hosts = loadHosts();
let PROXY_PUBLIC_IP = null; 

// --- HELPER FUNCTIONS ---

function loadHosts() {
  try {
    if (!fs.existsSync(HOSTS_FILE)) return new Map();
    const data = fs.readFileSync(HOSTS_FILE, "utf8");
    const json = JSON.parse(data);
    const map = new Map();
    for (const [host, targets] of Object.entries(json)) {
      // Store hostnames in lowercase, remove trailing dot
      map.set(host.toLowerCase().replace(/\.$/, ""), Array.isArray(targets) ? targets : [String(targets)]);
    }
    return map;
  } catch (e) {
    console.warn("Failed to load hosts.json:", e.message);
    return new Map();
  }
}

function isPrivateIp(ip) {
  if (!ip) return false;
  const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a,b] = [Number(v4[1]), Number(v4[2])];
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127;
  }
  return false;
}

function questionNameAndType(buf) {
  try {
    const p = dnsPacket.decode(buf);
    if (!p.questions || !p.questions.length) return null;
    const q = p.questions[0];
    return { name: q.name.replace(/\.$/,""), type: q.type || "A" };
  } catch { return null; }
}

function buildDnsAnswerPacket(queryBuffer, rrList) {
  const q = dnsPacket.decode(queryBuffer);
  return dnsPacket.encode({
    id: q.id,
    type: "response",
    flags: q.flags,
    questions: q.questions,
    // type: 1=A, 5=CNAME, 28=AAAA
    answers: rrList.map(r => ({ name: r.name, type: r.type, ttl: 60, class:"IN", data: r.data }))
  });
}

// --- MIDDLEWARE ---

// Middleware to parse raw DNS wire body
app.use((req,res,next)=>{
  if (req.headers["content-type"] === "application/dns-message" || req.method !== 'GET') {
    const chunks = [];
    req.on("data", c=>chunks.push(c));
    req.on("end", ()=>{ req.rawBody = Buffer.concat(chunks); next(); });
    req.on("error", next);
  } else {
    next();
  }
});

// 1. DOH HANDLER (Intercepts DNS queries)
app.all("/dns-query", async (req,res)=>{
  const accept = (req.headers.accept||"").toLowerCase();
  const wantsJson = accept.includes("application/dns-json") || req.query.name;
  
  try {
    let dnsBuf = null;
    let name = null;
    let type = "A";

    // --- A. Handle DNS WIRE format (GET or POST) ---
    if((req.method==="GET" && req.query.dns) || (req.method==="POST" && req.headers["content-type"]==="application/dns-message")){
      dnsBuf = req.method==="GET" 
        ? Buffer.from(req.query.dns.replace(/-/g,"+").replace(/_/g,"/")+"==","base64")
        : (req.rawBody || Buffer.alloc(0));
      
      const qinfo = questionNameAndType(dnsBuf);
      name = qinfo?.name.toLowerCase();
      type = qinfo?.type;
      
      if(name && hosts.has(name)) {
        const targets = hosts.get(name);
        if(targets.some(isPrivateIp)) {
          // LOCAL TARGET FOUND: Return CNAME pointing to the public tunnel host
          const rr = [{ name, type: 5, data: PROXY_PUBLIC_HOST }]; // Type 5 is CNAME
          res.setHeader("content-type","application/dns-message");
          const responseBuf = buildDnsAnswerPacket(dnsBuf, rr);
          res.setHeader("content-length", responseBuf.length);
          return res.status(200).send(responseBuf);
        }
      }
      
      // UPSTREAM FORWARD (Wire)
      const upstreamRes = await fetch(UPSTREAM_DOH, {
        method: "POST",
        headers: { "Content-Type":"application/dns-message", "Accept":"application/dns-message" },
        body: dnsBuf
      });
      const arrayBuffer = await upstreamRes.arrayBuffer();
      upstreamRes.headers.forEach((v,k)=>res.setHeader(k,v));
      return res.status(upstreamRes.status).send(Buffer.from(arrayBuffer));

    } 
    
    // --- B. Handle DNS JSON format (Mainly for debugging/clients) ---
    else if(wantsJson) {
      name = (req.query.name||req.body?.name||"").toString().toLowerCase();
      type = (req.query.type||req.body?.type||"A").toString().toUpperCase();

      if(name && hosts.has(name)) {
        const targets = hosts.get(name);
        if(targets.some(isPrivateIp)) {
          // LOCAL TARGET FOUND: Return CNAME pointing to the public tunnel host
          return res.json({ 
            Status:0, 
            Answer: [ 
              { name, type: 5, TTL: 60, data: PROXY_PUBLIC_HOST } // Type 5 is CNAME
            ] 
          });
        }
      }

      // UPSTREAM FORWARD (JSON)
      const r = await fetch(`${UPSTREAM_DOH}?name=${name}&type=${type}`,{ headers:{ Accept:"application/dns-json" } });
      const j = await r.json().catch(()=>null);
      if(j) return res.status(r.status).json(j);
      return res.status(502).json({ Status:2, Comment:"upstream failed" });
    }

    return res.status(404).send("Not Found");

  } catch(e){ 
    console.error("DoH Error:", e); 
    return res.status(500).send("Internal DNS error"); 
  }
});

// 2. PROXY HANDLER (Intercepts HTTP requests)
// This must run for all other routes that aren't /dns-query
app.use(async (req, res, next) => {
  // Extract only the hostname (no port)
  const hostHeader = (req.headers.host || "").split(":")[0].toLowerCase();

  // 1. Check if the requested host is one of our local targets
  if (!hosts.has(hostHeader)) {
    // Check if the requested host is the tunnel host itself (handle cases where browser hits the tunnel root)
    if (hostHeader === PROXY_PUBLIC_HOST.toLowerCase()) {
        return res.status(404).send(`Proxy tunnel established. Please configure a domain (e.g., samantha.femboy) to proxy.`);
    }
    return next(); // Not a target host, pass to next handler (which doesn't exist, so this will 404/500)
  }

  // 2. Identify the internal IP/Port
  const targets = hosts.get(hostHeader);
  const internalTarget = targets.find(t => isPrivateIp(t) || t.includes(":")); 

  if (!internalTarget) return next();

  // 3. Proxy the request to the internal service (e.g., 192.168.50.238)
  try {
    const targetUrl = `http://${internalTarget}${req.originalUrl || req.url}`;
    
    // CRITICAL FIX: The internal service needs the internal IP/Port as the Host header.
    const internalHostHeader = internalTarget; 
    
    const fetchOptions = {
      method: req.method,
      // Overwrite the Host header for the internal request
      headers: { ...req.headers, host: internalHostHeader }, 
      redirect: 'manual',
      // Ensure we can connect to internal HTTP without certificate issues
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

// --- SERVER STARTUP ---

async function startServer() {
  fs.watchFile(HOSTS_FILE, { interval: 1000 }, () => {
    console.log("Hosts file changed, reloading...");
    hosts = loadHosts();
  });
  
  await initProxyConfig(); // Resolves PROXY_PUBLIC_HOST's IP for logging/A records
  
  http.createServer(app).listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Proxy running on port ${PORT}`);
    console.log(`CNAME target for local hosts: ${PROXY_PUBLIC_HOST}`);
    console.log(`Hosts file loaded: ${hosts.size} entries.`);
  });
}

startServer();
