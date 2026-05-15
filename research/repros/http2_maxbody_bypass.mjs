import http2 from 'node:http2';
import { Readable } from 'node:stream';
import axios from '../../index.js';

const uploadBytes = 2 * 1024 * 1024;
const limit = 1024;

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

function makeUploadStream() {
  return Readable.from([Buffer.alloc(uploadBytes, 'a')]);
}

const server = http2.createServer();

server.on('stream', (stream) => {
  let received = 0;

  stream.on('data', (chunk) => {
    received += chunk.length;
  });

  stream.on('end', () => {
    const body = JSON.stringify({
      received,
      limit,
    });

    stream.respond({
      ':status': 200,
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
    });
    stream.end(body);
  });
});

let port;

try {
  port = await listen(server);

  const response = await axios.post(
    `http://127.0.0.1:${port}/upload`,
    makeUploadStream(),
    {
      httpVersion: 2,
      http2Options: {
        sessionTimeout: 10,
      },
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
      `HTTP/2 maxBodyLength bypass did not reproduce: ${JSON.stringify({
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
