/**
 * Shared utilities for SSL/TLS pinning API
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const DEFAULT_TARGET_URL = 'https://uatv2.patpat.lk';
const TARGET_URL = process.env.TARGET_URL || DEFAULT_TARGET_URL;
const TARGET_HOST = (() => {
  try {
    return new URL(TARGET_URL).hostname;
  } catch {
    return new URL(DEFAULT_TARGET_URL).hostname;
  }
})();

function loadCAs(certsDir, files) {
  const ca = [];
  for (const file of files) {
    const filePath = path.join(certsDir, file);
    const pem = fs.readFileSync(filePath, 'utf8');
    ca.push(pem);
  }
  return ca;
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(JSON.stringify(data, null, 2));
}

function runPinningRequest(hostname, ca) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname,
      port: 443,
      path: '/',
      method: 'GET',
      ca,
      rejectUnauthorized: true,
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        resolve({
          success: true,
          tlsHandshake: 'completed',
          httpStatus: res.statusCode,
          headers: {
            'content-type': res.headers['content-type'],
            'content-length': res.headers['content-length'],
          },
        });
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.setTimeout(10000, () => {
      req.destroy(new Error('Request timeout'));
    });

    req.end();
  });
}

function isCertError(err) {
  return (
    err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
    err.code === 'CERT_HAS_EXPIRED' ||
    err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
    err.code === 'UNABLE_TO_GET_ISSUER_CERT' ||
    err.code === 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' ||
    err.code === 'SELF_SIGNED_CERT_IN_CHAIN'
  );
}

module.exports = {
  TARGET_HOST,
  TARGET_URL,
  loadCAs,
  sendJson,
  runPinningRequest,
  isCertError,
};
