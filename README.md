# SSL/TLS Pinning API

Tests SSL/TLS certificate pinning against a target URL using Amazon Trust Services and Google Trust Services root CAs.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TARGET_URL` | The HTTPS URL to test (e.g. `https://uatv2.patpat.lk`) | `https://uatv2.patpat.lk` |
| `PORT` | HTTP server port | `3000` |

## Usage

```bash
# Default target (uatv2.patpat.lk)
node index.js

# Custom target URL
TARGET_URL=https://example.com node index.js

# Custom port
PORT=8080 node index.js

# Both
TARGET_URL=https://api.example.com PORT=8080 node index.js
```

## API Routes

- **GET /amazon** — Test pinning with Amazon Trust Services roots (for ACM-issued certs)
- **GET /google** — Test pinning with Google Trust Services roots (for GTS-issued certs)

## Project Structure

```
├── index.js
├── lib/utils.js
├── routes/
│   ├── amazon.js
│   └── google.js
└── certs/
    ├── amazon/   # AmazonRootCA1-4.pem
    └── google/   # r1.pem, r2.pem, r3.pem, r4.pem, gsr4.pem
```
