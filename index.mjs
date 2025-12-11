// doh-reverse-hosts.mjs
import fs from "fs";
import http from "http";
import https from "https";
import express from "express";
import fetch from "node-fetch";
import dnsPacket from "dns-packet";
import dns from "dns/promises";
import { URL } from "url";

const PORT = Number(process.env.PORT || 8053);
const UPSTREAM = process.env.UPSTREAM_DOH || "https://one.one.one.one/dns-query";
const HOSTS_FILE = process.env.HOSTS_FILE || "./hosts.json";
const PROXY_HOST = process.env.PROXY_HOST || "anywhere.nodemixaholic.com";
const IGNORE_TLS = (process.env.IGNORE_TLS || "true").toLowerCase() === "true";

// Mapping: client-visible hostname -> { targets: [IP], isLocal }
let mapping = new Map();

// Load hosts.json
function loadHosts() {
  try {
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

let hosts = loadHosts();
fs.watchFile(HOSTS_FILE, { interval: 1000 }, () => {
  console.log("Hosts file changed, reloading...");
  hosts = loadHosts();
});

// Detect private/local IP
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

// Resolve PROXY_HOST to IPs
async function resolveProxyHostIPs() {
  const results = [];
  try { results.push(...await dns.resolve4(PROXY_HOST).catch(()=>[])); } catch {}
  try { results.push(...await dns.resolve6(PROXY_HOST).catch(()=>[])); } catch {}
  return results.length ? results : ["127.0.0.1"];
}

// Resolve hostnames in hosts.json entries to IPs
async function resolveHostsEntry(entry) {
  const resolved = [];
  for (const t of entry) {
    if (isPrivateIp(t) || t.match(/^\d+(\.\d+){3}$/) || t.includes(":")) {
      resolved.push(t);
    } else {
      try {
        resolved.push(...await dns.resolve4(t).catch(()=>[]));
        resolved.push(...await dns.resolve6(t).catch(()=>[]));
      } catch(e){
        console.warn(`Failed to resolve ${t}: ${e.message}`);
      }
    }
  }
  return resolved;
}

// Forward DNS wire to upstream
async function forwardToUpstreamWire(buf) {
  const res = await fetch(UPSTREAM, {
    method: "POST",
    headers: {
      "Content-Type": "application/dns-message",
      "Accept": "application/dns-message"
    },
    body: buf
  });
  const arrayBuffer = await res.arrayBuffer();
  const headers = {};
  res.headers.forEach((v,k)=>headers[k]=v);
  return { buffer: Buffer.from(arrayBuffer), headers, status: res.status };
}

// Build DNS answer packet
function buildDnsAnswerPacket(queryBuffer, rrList) {
  const q = dnsPacket.decode(queryBuffer);
  return dnsPacket.encode({
    id: q.id,
    type: "response",
    flags: q.flags,
    questions: q.questions,
    answers: rrList.map(r => ({ name: r.name, type: r.type, ttl: r.ttl || 300, class: "IN", data: r.data }))
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

// Reverse proxy for private targets
app.use(async (req,res,next)=>{
  try {
    const host = (req.headers.host||"").split(":")[0].toLowerCase();
    const map = mapping.get(host);
    if(!map?.isLocal) return next();
    const targetIp = map.targets[0];
    if(!targetIp) return next();

    const url = `${req.protocol || "https"}://${targetIp}${req.originalUrl || req.url}`;
    const headers = {...req.headers, host};

    const agent = new https.Agent({ rejectUnauthorized: !IGNORE_TLS, servername: host });
    let upstreamRes;
    try { upstreamRes = await fetch(url,{ method:req.method, headers, body:req.rawBody, agent }); }
    catch { upstreamRes = await fetch(url,{ method:req.method, headers, body:req.rawBody }); }

    upstreamRes.headers.forEach((v,k)=>{
      if(!["connection","keep-alive","transfer-encoding","upgrade"].includes(k)) res.setHeader(k,v);
    });
    res.status(upstreamRes.status);
    res.send(Buffer.from(await upstreamRes.arrayBuffer()));
  } catch(e){ console.error("Proxy error:", e); res.status(502).send("Bad Gateway"); }
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

        if(localTargets.length){
          const proxyIps = await resolveProxyHostIPs();
          mapping.set(name,{ targets: localTargets, isLocal:true });
          const rr = proxyIps.map(ip=>({ name, type: ip.includes(":")?"AAAA":"A", data: ip }));
          forwardToUpstreamWire(dnsBuf).catch(()=>{});
          return sendWire(res, buildDnsAnswerPacket(dnsBuf, rr));
        }

        if(publicTargets.length){
          mapping.set(name,{ targets: publicTargets, isLocal:false });
          const rr = publicTargets.map(ip=>({ name, type: ip.includes(":")?"AAAA":"A", data: ip }));
          forwardToUpstreamWire(dnsBuf).catch(()=>{});
          return sendWire(res, buildDnsAnswerPacket(dnsBuf, rr));
        }
      }

      // fallback upstream
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

        if(localTargets.length){
          const proxyIps = await resolveProxyHostIPs();
          mapping.set(name,{ targets: localTargets, isLocal:true });
          const rr = proxyIps.map(ip=>({ name, type: ip.includes(":")?"AAAA":"A", data: ip }));
          forwardToUpstreamWire(dnsBuf).catch(()=>{});
          return sendWire(res, buildDnsAnswerPacket(dnsBuf, rr));
        }

        if(publicTargets.length){
          mapping.set(name,{ targets: publicTargets, isLocal:false });
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

        if(localTargets.length){
          const proxyIps = await resolveProxyHostIPs();
          mapping.set(lower,{ targets: localTargets, isLocal:true });
          return res.json({ Status:0, Answer: proxyIps.map(ip=>({ name:lower, type:ip.includes(":")?28:1, TTL:300, data:ip })) });
        }

        if(publicTargets.length){
          mapping.set(lower,{ targets: publicTargets, isLocal:false });
          return res.json({ Status:0, Answer: publicTargets.map(ip=>({ name:lower, type:ip.includes(":")?28:1, TTL:300, data:ip })) });
        }
      }

      // fallback upstream
      const u = new URL(UPSTREAM);
      u.searchParams.set("name", name);
      u.searchParams.set("type", type);
      const r = await fetch(String(u), { headers:{ Accept:"application/dns-json" } });
      const j = await r.json().catch(()=>null);
      if(j) return res.status(r.status).json(j);
      return res.status(502).json({ Status:2, Comment:"upstream failed" });
    }

    return res.status(404).send("Not Found");
  } catch(e){ console.error(e); return res.status(500).send("Internal error"); }
});

http.createServer(app).listen(PORT,()=>{
  console.log(`DOH + Reverse Proxy listening on http://0.0.0.0:${PORT}`);
  console.log(`Upstream DOH: ${UPSTREAM}`);
  console.log(`Hosts file: ${HOSTS_FILE}`);
  console.log(`Proxy host: ${PROXY_HOST}`);
  console.log(`IGNORE_TLS: ${IGNORE_TLS}`);
});
