// doh-server.js
// A simple DNS over HTTPS (DoH) server in Node.js
// Features:
// - Forwards standard DNS queries to an upstream DoH resolver (e.g., Google DNS).
// - Overrides resolutions for domains listed in a hosts.json file (like /etc/hosts).
// - Handles both GET (base64url encoded) and POST (binary DNS message) requests.
// - Supports DNS message compression via dns-packet library.
// - Assumes A records for hosts file (IPv4); extend for AAAA if needed.
// - Runs over HTTPS; provide your own server.key and server.crt (use mkcert for local testing).

const https = require('https');
const fs = require('fs');
const dnsPacket = require('dns-packet');
const axios = require('axios');
const express = require('express');
const bodyParser = require('body-parser');

// Configuration
const UPSTREAM_DOH_URL = 'https://one.one.one.one/dns-query'; // User-provided regular DoH server
const HOSTS_FILE = './hosts.json'; // e.g., { "example.local": "192.168.1.100", "public.example.com": "8.8.8.8" }
const PORT = 4442; // HTTPS port; change if needed

// Load hosts mappings
let hosts = {};
try {
  hosts = JSON.parse(fs.readFileSync(HOSTS_FILE, 'utf8'));
  console.log('Loaded hosts:', Object.keys(hosts));
} catch (err) {
  console.error('Error loading hosts.json:', err);
}

// Load SSL certs (generate with mkcert or obtain from CA)
const options = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.crt'),
};

const app = express();

// Middleware to handle raw binary body for POST
app.use(bodyParser.raw({ type: 'application/dns-message', limit: '10kb' }));

// DoH endpoint: /dns-query
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

    const name = question.name.toLowerCase();
    const type = question.type; // e.g., 'A', 'AAAA', etc.

    // Check if in local hosts (support A for now; add cases for AAAA, etc.)
    if (hosts[name] && type === 'A') {
      // Craft local response
      const response = {
        id: dnsMessage.id,
        type: 'response',
        flags: dnsPacket.RECURSION_AVAILABLE | dnsPacket.AUTHORITATIVE | dnsPacket.RECURSION_DESIRED,
        questions: dnsMessage.questions,
        answers: [{
          name: name,
          type: 'A',
          class: 'IN',
          ttl: 300, // 5 minutes
          data: hosts[name], // IP string
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

// Create HTTPS server
https.createServer(options, app).listen(PORT, () => {
  console.log(`DoH server listening on https://localhost:${PORT}/dns-query`);
});
