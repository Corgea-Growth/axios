import http from 'node:http';
import axios from '../../index.js';

const uploadBytes = 2 * 1024 * 1024;
const limit = 1024;
const chunkSize = 64 * 1024;

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

function makeReadableStream() {
  let sent = 0;

  return new ReadableStream({
    pull(controller) {
      if (sent >= uploadBytes) {
        controller.close();
        return;
      }

      const size = Math.min(chunkSize, uploadBytes - sent);
      sent += size;
      controller.enqueue(new Uint8Array(size));
    },
  });
}

const server = http.createServer((req, res) => {
  let received = 0;

  req.on('data', (chunk) => {
    received += chunk.length;
  });

  req.on('end', () => {
    const body = JSON.stringify({
      received,
      limit,
    });

    res.writeHead(200, {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
    });
    res.end(body);
  });
});

let port;

try {
  port = await listen(server);

  const response = await axios.post(
    `http://127.0.0.1:${port}/upload`,
    makeReadableStream(),
    {
      adapter: 'fetch',
      maxBodyLength: limit,
      headers: {
        'content-type': 'application/octet-stream',
      },
    }
  );

  const evidence =
    typeof response.data === 'string' ? JSON.parse(response.data) : response.data;

  console.log(
    JSON.stringify({
      status: response.status,
      ...evidence,
    })
  );

  if (response.status !== 200 || evidence.received !== uploadBytes) {
    throw new Error(
      `fetch stream maxBodyLength bypass did not reproduce: ${JSON.stringify({
        status: response.status,
        ...evidence,
      })}`
    );
  }
} finally {
  if (port !== undefined) {
    await close(server);
  }
}
