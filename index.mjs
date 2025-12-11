// reverse-doh-proxy.mjs
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

// PROXY_PUBLIC_HOST is the hostname exposed by the Cloudflare Tunnel (e.g., anywhere.nodemixaholic.com)
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
    answers: rrList.map(r => ({ name: r.name, type: r.type, ttl: 60, class:"IN", data: r.data }))
  });
}

// ** This function was causing the ReferenceError because it was called before its definition in the module structure.
//    Defining it here resolves the scope issue. **
async function initProxyConfig() {
  if (isPrivateIp(PROXY_PUBLIC_HOST) || PROXY_PUBLIC_HOST.match(/^\d+(\.\d+){3}$/)) {
    PROXY_PUBLIC_IP = PROXY_PUBLIC_HOST;
  } else {
    try {
      console.log(`Resolving PROXY_PUBLIC_HOST (${PROXY_PUBLIC_HOST}) for A record fallback...`);
      const { address } = await dnsLookup(PROXY_PUBLIC_HOST);
      PROXY_PUBLIC_IP = address;
      console.log(`Resolved PROXY_PUBLIC_HOST for A-records: ${PROXY_PUBLIC_IP}`);
    } catch (e) {
      console.warn(`Could not resolve PROXY_PUBLIC_HOST, relying solely on CNAME for local targets.`);
    }
  }
}

// --- MIDDLEWARE ---

// Middleware to parse raw DNS wire body
app.use((req,res,next)=>{
  if (req.headers["content-type"] === "application/dns-message" || (req.method !== 'GET' && req.headers['content-length'] > 0)) {
    const chunks = [];
    req.on("data", c=>chunks.push(c));
    req.on("end", ()=>{ req.rawBody = Buffer.concat(chunks); next(); });
    req.on("error", next);
  } else {
    next();
  }
});

// 1. DOH HANDLER
app.all("/dns-query", async (req,res)=>{
  const accept = (req.headers.accept||"").toLowerCase();
  const wantsJson = accept.includes("application/dns-json") || req.query.name;
  
  try {
    let dnsBuf = null;

    // --- A. Handle DNS WIRE format (GET or POST) ---
    if((req.method==="GET" && req.query.dns) || (req.method==="POST" && req.headers["content-type"]==="application/dns-message")){
      dnsBuf = req.method==="GET" 
        ? Buffer.from(req.query.dns.replace(/-/g,"+").replace(/_/g,"/")+"==","base64")
        : (req.rawBody || Buffer.alloc(0));
      
      const qinfo = questionNameAndType(dnsBuf);
      const name = qinfo?.name.toLowerCase();
      
      if(name && hosts.has(name) && hosts.get(name).some(isPrivateIp)) {
        // LOCAL TARGET FOUND: Return CNAME (Type 5)
        const rr = [{ name, type: 5, data: PROXY_PUBLIC_HOST }];
        res.setHeader("content-type","application/dns-message");
        const responseBuf = buildDnsAnswerPacket(dnsBuf, rr);
        res.setHeader("content-length", responseBuf.length);
        return res.status(200).send(responseBuf);
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
    
    // --- B. Handle DNS JSON format ---
    else if(wantsJson) {
      const name = (req.query.name||req.body?.name||"").toString().toLowerCase();

      if(name && hosts.has(name) && hosts.get(name).some(isPrivateIp)) {
          // LOCAL TARGET FOUND: Return CNAME (Type 5)
          return res.json({ 
            Status:0, 
            Answer: [ 
              { name, type: 5, TTL: 60, data: PROXY_PUBLIC_HOST } 
            ] 
          });
      }

      // UPSTREAM FORWARD (JSON)
      const type = (req.query.type||req.body?.type||"A").toString().toUpperCase();
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

// 2. PROXY HANDLER (Stateless HTTP/S Reverse Proxy)
app.use(async (req, res, next) => {
  const hostHeader = (req.headers.host || "").split(":")[0].toLowerCase();

  // If the request is for the public host itself, don't proxy (prevents proxy loop)
  if (hostHeader === PROXY_PUBLIC_HOST.toLowerCase()) {
      return next(); 
  }

  // Check if the requested host is one of our local targets
  if (!hosts.has(hostHeader)) {
    return next(); 
  }

  // Identify the internal IP/Port
  const targets = hosts.get(hostHeader);
  const internalTarget = targets.find(t => isPrivateIp(t) || t.includes(":")); 

  if (!internalTarget) return next();

  // Proxy the request
  try {
    const targetUrl = `http://${internalTarget}${req.originalUrl || req.url}`;
    
    // CRITICAL FIX: Use the internal IP/Port as the Host header for the internal request.
    const internalHostHeader = internalTarget; 
    
    const fetchOptions = {
      method: req.method,
      // Overwrite the Host header for the internal request
      headers: { ...req.headers, host: internalHostHeader }, 
      redirect: 'manual',
      // Allow self-signed certs internally (though we use http:// to avoid this)
      agent: new http.Agent({ rejectUnauthorized: false }) 
    };

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      fetchOptions.body = req.rawBody;
    }

    const upstreamRes = await fetch(targetUrl, fetchOptions);

    // Forward headers
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
  
  await initProxyConfig(); 
  
  http.createServer(app).listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Proxy running on port ${PORT}`);
    console.log(`CNAME target for local hosts: ${PROXY_PUBLIC_HOST}`);
    console.log(`Hosts file loaded: ${hosts.size} entries.`);
  });
}

// Execute the startup function
startServer();
