// doh-server.js
// A simple DNS over HTTPS (DoH) server in Node.js with proxy functionality
// Features:
// - Forwards standard DNS queries to an upstream DoH resolver (e.g., Cloudflare DNS).
// - For domains in hosts.json, resolves to the server's public IP (A record).
// - Acts as a reverse proxy: For non-DoH requests, checks the Host header; if it matches hosts.json, proxies to the target IP:port in hosts.json.
// - Assumes hosts.json format: { "example.local": "192.168.1.100:8000", "public.example.com": "8.8.8.8:80" } (port optional, defaults to 80).
// - Handles both GET (base64url encoded) and POST (binary DNS message) for DoH.
// - Supports DNS message compression via dns-packet.
// - Runs over HTTPS; provide your own server.key and server.crt (use Let's Encrypt for production with multi-domain support).
// - IMPORTANT: For proxying to work with HTTPS, your SSL cert must be valid for the proxied domains (e.g., SAN cert or wildcard). Self-signed won't validate on clients.

const https = require('https');
const fs = require('fs');
const dnsPacket = require('dns-packet');
const axios = require('axios');
const express = require('express');
const bodyParser = require('body-parser');
const httpProxy = require('http-proxy');

// Configuration
const UPSTREAM_DOH_URL = 'https://one.one.one.one/dns-query'; // User-provided regular DoH server
const HOSTS_FILE = './hosts.json'; // e.g., { "example.local": "192.168.1.100:8000", "public.example.com": "8.8.8.8:80" }
const PUBLIC_IP = 'your.public.ip.here'; // Set this to your server's public IPv4 address (e.g., '203.0.113.1')
const PORT = 4442; // HTTPS port; change if needed

// Load hosts mappings
let hosts = {};
try {
  hosts = JSON.parse(fs.readFileSync(HOSTS_FILE, 'utf8'));
  console.log('Loaded hosts:', Object.keys(hosts));
} catch (err) {
  console.error('Error loading hosts.json:', err);
}

// Load SSL certs (obtain a cert valid for all proxied domains in production)
const options = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.crt'),
};

const app = express();
const proxy = httpProxy.createProxyServer({});

// Middleware to handle raw binary body for POST (DoH)
app.use(bodyParser.raw({ type: 'application/dns-message', limit: '10kb' }));

// Proxy middleware for non-DoH requests
app.use((req, res, next) => {
  if (req.path.startsWith('/dns-query')) {
    return next(); // Handle as DoH
  }

  const host = (req.headers.host || '').split(':')[0].toLowerCase().replace(/\.$/, '');
  const target = hosts[host];

  if (target) {
    let targetUrl = `http://${target}`;
    if (!target.includes(':')) {
      targetUrl += ':80'; // Default port if not specified
    }
    console.log(`Proxying ${host} to ${targetUrl}`);
    proxy.web(req, res, { target: targetUrl });
  } else {
    res.status(404).send('Not Found');
  }
});

// DoH endpoints: /dns-query
app.get('/dns-query', handleDoHRequest);
app.post('/dns-query', handleDoHRequest);

async function handleDoHRequest(req, res) {
  let dnsMessage;
  try {
    if (req.method === 'GET') {
      const base64Dns = req.query.dns;
      if (!base64Dns) {
        return res.status(400).send('Missing dns parameter');
      }
      // Decode base64url
      const buffer = Buffer.from(base64Dns.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      dnsMessage = dnsPacket.decode(buffer);
    } else if (req.method === 'POST') {
      if (req.headers['content-type'] !== 'application/dns-message') {
        return res.status(415).send('Unsupported Content-Type');
      }
      dnsMessage = dnsPacket.decode(req.body);
    } else {
      return res.status(405).send('Method Not Allowed');
    }

    // Extract the first question (assume single question for simplicity)
    const question = dnsMessage.questions[0];
    if (!question) {
      return res.status(400).send('No question in DNS message');
    }

    const name = question.name.toLowerCase().replace(/\.$/, '');
    const type = question.type; // e.g., 'A', 'AAAA', etc.

    // Check if in local hosts (support A for now; forward others or add AAAA if needed)
    if (hosts[name] && type === 'A') {
      // Craft local response resolving to public IP
      const response = {
        id: dnsMessage.id,
        type: 'response',
        flags: dnsPacket.RECURSION_AVAILABLE | dnsPacket.AUTHORITATIVE | dnsPacket.RECURSION_DESIRED,
        questions: dnsMessage.questions,
        answers: [{
          name: question.name,
          type: 'A',
          class: 'IN',
          ttl: 300, // 5 minutes
          data: PUBLIC_IP, // Resolve to server's public IP
        }],
      };

      // Encode response
      const encoded = dnsPacket.encode(response);

      // Set headers
      res.set('Content-Type', 'application/dns-message');
      res.set('Content-Length', encoded.length);
      return res.send(encoded);
    } else {
      // Forward to upstream
      let upstreamResponse;
      if (req.method === 'GET') {
        // Forward as GET
        const upstreamUrl = `${UPSTREAM_DOH_URL}?dns=${encodeURIComponent(req.query.dns)}`;
        upstreamResponse = await axios.get(upstreamUrl, {
          headers: { Accept: 'application/dns-message' },
          responseType: 'arraybuffer',
        });
      } else {
        // Forward as POST
        upstreamResponse = await axios.post(UPSTREAM_DOH_URL, req.body, {
          headers: { 'Content-Type': 'application/dns-message' },
          responseType: 'arraybuffer',
        });
      }

      // Relay the response
      res.set('Content-Type', 'application/dns-message');
      res.set('Content-Length', upstreamResponse.data.byteLength);
      return res.send(Buffer.from(upstreamResponse.data));
    }
  } catch (err) {
    console.error('Error handling DoH request:', err);
    res.status(500).send('Internal Server Error');
  }
}

// Handle proxy errors
proxy.on('error', (err, req, res) => {
  console.error('Proxy error:', err);
  res.status(502).send('Bad Gateway');
});

// Create HTTPS server
https.createServer(options, app).listen(PORT, () => {
  console.log(`DoH + Proxy server listening on https://localhost:${PORT}/dns-query`);
});
