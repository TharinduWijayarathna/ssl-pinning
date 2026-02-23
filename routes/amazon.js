/**
 * Amazon Trust Services SSL/TLS pinning route
 */

const path = require('path');
const {
  TARGET_URL,
  TARGET_HOST,
  loadCAs,
  sendJson,
  runPinningRequest,
  isCertError,
} = require('../lib/utils');

const CERTS_DIR = path.join(__dirname, '..', 'certs', 'amazon');
const CA_FILES = [
  'AmazonRootCA1.pem',
  'AmazonRootCA2.pem',
  'AmazonRootCA3.pem',
  'AmazonRootCA4.pem',
];

function handleAmazonRoute(req, res) {
  const timestamp = new Date().toISOString();
  const basePayload = {
    route: 'amazon',
    pinning: {
      trustStore: 'Amazon Trust Services',
      rootsUsed: CA_FILES,
      target: TARGET_URL,
    },
    timestamp,
  };

  let ca;
  try {
    ca = loadCAs(CERTS_DIR, CA_FILES);
  } catch (err) {
    return sendJson(res, 500, {
      ...basePayload,
      success: false,
      error: {
        code: 'CA_LOAD_FAILED',
        message: err.message,
        description: `Failed to load one or more Amazon root CA files from ${CERTS_DIR}.`,
        detail: err.stack,
      },
    });
  }

  runPinningRequest(TARGET_HOST, ca)
    .then((result) => {
      sendJson(res, 200, {
        ...basePayload,
        success: true,
        result: {
          tlsHandshake: result.tlsHandshake,
          certificateValidation: 'passed',
          chainAnchorsTo: 'Amazon Trust Services root CA',
          httpStatus: result.httpStatus,
          message: 'Server certificate chain validated against trusted Amazon root CAs.',
        },
      });
    })
    .catch((err) => {
      const errorPayload = {
        code: err.code || 'UNKNOWN_ERROR',
        message: err.message,
      };

      if (isCertError(err)) {
        errorPayload.description =
          "The server's certificate chain does not anchor to any of the trusted Amazon root CAs.";
        errorPayload.reason =
          'The target uses Google Trust Services (GTS) certificates, not Amazon Trust Services (ACM).';
        errorPayload.recommendation =
          'Use the /google route for targets with GTS-issued certificates.';
      } else if (err.message === 'Request timeout') {
        errorPayload.description = 'The HTTPS request to the target timed out.';
        errorPayload.recommendation = 'Check network connectivity and target availability.';
      } else {
        errorPayload.description =
          'An unexpected error occurred during the TLS handshake or HTTP request.';
      }

      sendJson(res, 502, {
        ...basePayload,
        success: false,
        error: errorPayload,
      });
    });
}

module.exports = { handleAmazonRoute };
