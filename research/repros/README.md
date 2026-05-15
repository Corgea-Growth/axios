# Security finding reproducers

Each script is self-contained: it spins up a local server, runs axios from
this repository (`../../index.js`), prints what the server received, and
exits non-zero if axios is **not** vulnerable. They are intended to be run
against this checkout to confirm a finding still reproduces, and rerun
against a candidate fix to confirm regression coverage.

| PoC | Finding | Severity |
| --- | --- | --- |
| `pp_nested_option_gadgets.mjs` | Nested option objects (`auth`, `paramsSerializer`) reintroduce prototype-pollution gadgets | high |
| `http2_maxbody_bypass.mjs` | HTTP/2 streamed uploads bypass `maxBodyLength` enforcement | medium |
| `fetch_stream_maxbody_bypass.mjs` | Fetch adapter `ReadableStream` uploads bypass `maxBodyLength` enforcement | medium |

## Run

```bash
node research/repros/pp_nested_option_gadgets.mjs
node research/repros/http2_maxbody_bypass.mjs
node research/repros/fetch_stream_maxbody_bypass.mjs
```

All three currently print `VULNERABLE: ...` and exit 0 on `v1.x` HEAD
(axios v1.16.1).

## Notes

- `pp_nested_option_gadgets.mjs` simulates a pre-existing prototype-pollution
  primitive by setting non-enumerable accessors on `Object.prototype`, then
  passes empty placeholder objects (`auth: {}`, `paramsSerializer: {}`) to
  axios. The fix in `mergeConfig` only hardens the top-level config; nested
  plain objects are still cloned to ordinary `{}` containers.
- `http2_maxbody_bypass.mjs` uses cleartext HTTP/2 (h2c). The PoC must NOT
  set `maxRedirects: 0`, because that flag activates the existing HTTP/1
  byte-counting wrapper and would mask the bug under test.
- `fetch_stream_maxbody_bypass.mjs` posts a live `ReadableStream` so the
  body length cannot be inferred before dispatch, which is the precondition
  for the bypass.
