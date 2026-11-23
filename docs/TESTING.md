# Testing

```bash
npm test           # unit, security, route and research tests (Node built-in test runner)
npm run test:e2e   # browser integration tests (installed Chrome or Edge via playwright-core)
npm run check      # syntax + generated pages + vendored libraries are up to date
```

`test:e2e` needs Google Chrome or Microsoft Edge installed. Choose with `PLAYWRIGHT_CHANNEL=chrome|msedge`. If neither is found the tests are skipped, not passed silently: the runner reports them as skipped.

## Suites

| File | Covers |
|---|---|
| `tests/shield-core.test.mjs` | Raw-message detection; folded headers and RFC 2047; multipart MIME, attachment signatures; Unicode and UTF-16 offsets; malformed MIME; input validation; PSL registrable domains (co.uk, github.io); HTML link extraction (entities, comments, forms); text URL trimming; suspicious URL indicators (IP, obfuscated IP, userinfo, IDN, shortener, deep subdomain, port, brand-in-subdomain, redirect param, javascript:); benign URLs → no findings; link-text mismatch by registrable domain; look-alikes (paypa1, rnicrosoft, Cyrillic homograph) and non-matches; negation/quotation/awareness safeguards; OTP/payment/impersonation; attachment metadata; auth claims unverified; forged "pass" never lowers index; Received ordering; end-to-end suspicious and benign fixtures; index caps, bounds and determinism; `.eml` bytes vs paste parity; report excludes body |
| `tests/shield-security.test.mjs` | SSRF allow-list; providers contacted, never the URL itself; credentials/fragments stripped; private hosts refused; provider failure → "unavailable"; endpoint 503 when unconfigured; status endpoints leak no secrets; 401/400/403/413/415 paths; 429 rate limiting and fail-closed store; public mode requires durable limiter; AI consent/auth/size; prompt-injection grounding (invented quotes discarded); provider failure 502; strict secret comparison; XSS-safe HTML export; CSV formula injection; secret scrubbing; repository secret scan |
| `tests/shield-routes.test.mjs` | All routes exist; Shield pages load existing assets and two-area nav; CSP compatibility (no inline script/style/handlers); every internal link/asset resolves; page modules export `init`; no `innerHTML` in UI; `vercel.json` CSP and API no-store; vendored file hashes |
| `tests/e2e/shield.e2e.mjs` | Real browser with production CSP: scanner end-to-end; benign and hard-negative not over-flagged; `.eml` import and JSON/CSV/HTML export; hostile HTML inert; analysis/links/headers/reports pages; headers-only paste; opt-in history, dashboard status, delete-all; mobile menu and no horizontal overflow (with results expanded); keyboard skip link and tab arrows; homepage and research routes load. Every page fails on console errors, CSP violations, unexpected dialogs or off-origin requests. |
| `tests/engine.test.mjs`, `spans.test.mjs`, `evaluation.test.mjs`, `api.test.mjs`, `routes.test.mjs` | Original CAP 6640 research suites (unchanged) |

## Fixtures

`tests/fixtures/*.eml|txt` are synthetic, use reserved `.example` domains and RFC 5737 documentation IPs, and contain no real personal data.

## Not yet covered (known gaps)

- Fuzzing / ReDoS stress testing of parsers and regexes.
- Live provider integration tests (require credentials; only mocked today).
- Automated contrast measurement (palette was chosen for WCAG AA but not machine-verified) and screen-reader testing with NVDA/VoiceOver.
- Authentication, authorization and tenant-isolation tests (no accounts exist).
- Detection-quality evaluation on a representative, permissioned benchmark (see `PRODUCT_STATUS.md`).
