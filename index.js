#!/usr/bin/env node
/**
 * SSL/TLS Pinning API Server
 *
 * Exposes /amazon and /google routes that test certificate pinning against
 * https://uatv2.patpat.lk using Amazon Trust Services and Google Trust Services
 * root CAs respectively. Returns detailed JSON responses for success and errors.
 */

const http = require('http');
const { sendJson } = require('./lib/utils');
const { handleAmazonRoute } = require('./routes/amazon');
const { handleGoogleRoute } = require('./routes/google');

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://localhost:${PORT}`);

  if (url.pathname === '/amazon') {
    return handleAmazonRoute(req, res);
  }
  if (url.pathname === '/google') {
    return handleGoogleRoute(req, res);
  }

  sendJson(res, 404, {
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: 'Route not found',
      availableRoutes: ['/amazon', '/google'],
      description:
        'Use GET /amazon to test Amazon Trust Services pinning, GET /google for Google Trust Services.',
    },
    timestamp: new Date().toISOString(),
  });
});

server.listen(PORT, () => {
  console.log(`SSL Pinning API server listening on http://localhost:${PORT}`);
  console.log('  GET /amazon  - Test pinning with Amazon Trust Services roots');
  console.log('  GET /google  - Test pinning with Google Trust Services roots');
});
