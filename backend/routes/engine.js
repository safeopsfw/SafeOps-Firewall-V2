// Firewall Engine Proxy Routes
// Proxies /api/engine/* → firewall engine REST API at localhost:50052/api/v1/*

const express = require('express');
const http = require('http');
const router = express.Router();

const ENGINE_HOST = '127.0.0.1';
const ENGINE_PORT = 8443;

function proxyToEngine(req, res) {
  const enginePath = '/api/v1' + req.path;
  const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';

  const options = {
    hostname: ENGINE_HOST,
    port: ENGINE_PORT,
    path: enginePath + query,
    method: req.method,
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.status(proxyRes.statusCode);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error('[ENGINE PROXY] Error:', err.message);
    res.status(503).json({ error: 'Firewall engine unreachable', detail: err.message });
  });

  if (req.body && Object.keys(req.body).length > 0) {
    const body = JSON.stringify(req.body);
    proxyReq.setHeader('Content-Length', Buffer.byteLength(body));
    proxyReq.write(body);
  }

  proxyReq.end();
}

// Catch-all: proxy all methods
router.all('*', proxyToEngine);

module.exports = router;
