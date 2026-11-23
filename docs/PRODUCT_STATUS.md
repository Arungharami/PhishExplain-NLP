# Product status — PhishExplain Shield

Last updated: 2026-11-23 · Engine `phishexplain-shield-local` 1.0.0 · Ruleset `shield-lang-1`

Vocabulary: **Implemented** (code exists) · **Tested locally** (automated tests pass) · **Deployed** (in the production build) · **Configured** (credentials set) · **Operational** (verified working in production) · **Externally validated** (independently evaluated) · **Planned** (not implemented).

## Audit findings that were fixed (Phase 1)

| Finding | Resolution |
|---|---|
| `/security/` was live but referenced `/shield.js` and `/shield.css`, which did not exist, so the page was unstyled and non-functional | Implemented the Shield design system, entry point and page modules; route tests assert every referenced asset exists |
| `security-engine.js` was committed but imported by nothing; regex-only header parsing; host comparison by string equality | Replaced by `shield/core/*` (MIME parser, PSL domains); orphan file removed |
| Homepage was the research landing page | New product homepage at `/`; former homepage preserved unchanged at `/nlp/` and linked from every research page |
| No security headers beyond basics | Strict CSP for product pages, relaxed CSP for research pages, `Permissions-Policy`, COOP, API `no-store` |
| CI only syntax-checked 4 files | CI now runs `npm ci`, audit, generated-file checks, 74 Node tests and 10 Chrome tests |

Research features, data (`data/`), split manifest, evaluator and research docs are unchanged. The research tests pass.

## Capability status

| Capability | Status |
|---|---|
| Product homepage, 7 Shield pages, two-area navigation | Implemented · Tested locally · Deployed (see below) |
| Paste body / raw message / `.eml` / `.txt` input, 5 MB limit | Implemented · Tested locally · Deployed |
| MIME parsing (postal-mime 4.2.1), folded headers, RFC 2047, multipart, attachments | Implemented · Tested locally · Deployed |
| URL inspection without visiting (PSL via tldts 7.5.5) | Implemented · Tested locally · Deployed |
| Sender identity checks | Implemented · Tested locally · Deployed |
| Received-hop timeline; SPF/DKIM/DMARC **as unverified claims** | Implemented · Tested locally · Deployed |
| Attachment metadata checks (no malware scanning) | Implemented · Tested locally · Deployed |
| Social-engineering language with negation/quotation safeguards | Implemented · Tested locally · Deployed |
| Explanations (evidence, source, why, false positives, action) | Implemented · Tested locally · Deployed |
| Uncalibrated attention index | Implemented · Tested locally · Deployed · **Not calibrated** |
| JSON / CSV / HTML / print-to-PDF reports, JSON re-import | Implemented · Tested locally · Deployed |
| Local history, workflow states, notes, retention, delete-all | Implemented · Tested locally · Deployed (browser only) |
| URL reputation (GSB v5, URLhaus, VirusTotal) | Implemented · Tested locally with mocks · Deployed · **Not configured → shows "Reputation lookup unavailable"** |
| AI contextual analysis (OpenAI, grounded) | Implemented · Tested locally with mocks · Deployed · **Not configured → shows "unavailable"** |
| Durable rate limiting (Upstash/Vercel KV) | Implemented · Tested locally with mocks · **Not configured** (per-instance fallback) |
| User accounts, cloud storage, RBAC, tenant isolation | **Planned** — not implemented |
| Gmail / Microsoft 365 integrations | **Planned** — design only (docs/INTEGRATIONS.md) |
| Continuous inbox protection, blocking, quarantine | **Not offered** |
| Detection accuracy (FPR/FNR/precision/recall) | **Not measured** |

## Test results (local, 2026-11-23, Node 26.4.0, Windows 11, Chrome)

- `npm test`: **74 passed, 0 failed**. That breaks down as 29 Shield core, 16 security, 8 route/asset and 21 original research tests.
- `npm run test:e2e`: **10 passed, 0 failed** in headless Chrome with the production CSP enforced.
- `npm run check`: syntax OK; generated pages and vendored libraries are current.
- `npm audit`: 0 vulnerabilities.

### Measured local performance (Node, median of 40 runs)

| Input | Median | p95 |
|---|---|---|
| Typical synthetic samples (0.3–2 KB) | 0.3–1.2 ms | ≤ 1.5 ms |
| 180 KB plain-text message | 56.6 ms | 58.9 ms |
| Adversarial inputs (200 KB angle-bracket soup, 100k-label host, 13k forms, 3,000 headers) | all < 0.2 s | — |

Browser timing is similar but varies by device. These are engine timings only, not end-user latency.

## Product evaluation (Phase 15) — not yet possible

No representative, permissioned email benchmark exists for this project. False-positive rate, false-negative rate, precision, recall and detection coverage are therefore **not measured and not claimed**. The bundled samples and fixtures are synthetic regression tests, not an evaluation set. The CAP 6640 corpus is synthetic and is reserved for the research study.

What a valid evaluation needs:
1. A permissioned corpus of real phishing and legitimate mail, with consent or a licensed public dataset with clear terms. It must include BEC, newsletters, transactional mail and security notices.
2. Independent labels.
3. A frozen engine version.
4. Per-category coverage plus FPR/FNR at chosen index thresholds, with confidence intervals.
5. Provider failure and latency measurements once reputation and AI are configured.

## Remaining blockers and owner actions

1. **Credentials (optional features):** set `SHIELD_ACCESS_KEY` and at least one of the reputation provider keys and/or `OPENAI_API_KEY`, plus `UPSTASH_REDIS_REST_URL`/`TOKEN`, in Vercel (see `.env.example`). Until then, those features correctly report "unavailable".
2. **Provider terms:** Google Safe Browsing and the VirusTotal public API are non-commercial. An organizational or commercial service needs Google Web Risk and a licensed VirusTotal tier.
3. **Accounts/storage:** choose a managed authentication provider and database before building server-side history, RBAC and tenant isolation.
4. **Evaluation:** obtain a permissioned benchmark (above).
5. **Independent review:** a security review/penetration test and an accessibility audit (contrast and screen readers).

## Deployment (verified 2026-11-23)

- **Commit:** `94d6f55` on `main` (product code). Later commits change docs and test tooling only.
- **GitHub Actions** run 45282253412: success. The log shows 74/74 Node tests and 10/10 Chrome tests, 0 skipped, `npm audit` with 0 vulnerabilities, and generated pages and vendored libraries current.
- **Vercel** commit status: `success` ("Deployment has completed"), existing project `phishexplain-nlp`. No new project was created.
- **Production smoke test** (https://phishexplain-nlp.vercel.app):
  - All 18 page routes, the Shield and vendor assets, and the research assets return 200.
  - `/tests/…`, `/.env` and the removed `/security-engine.js` return 404.
  - `GET /api/reputation` and `GET /api/ai-analysis` return `available:false` and expose no secrets.
  - `POST /api/reputation` returns 503 "Reputation lookup unavailable".
  - `/api/infer` (research) still returns 200.
  - Strict CSP, `X-Frame-Options: DENY`, `Permissions-Policy`, COOP, `nosniff` and `Referrer-Policy` are served on `/security/`. The relaxed research CSP is served on `/lab/`.
- **Browser suite against production** (`SHIELD_BASE_URL=https://phishexplain-nlp.vercel.app npm run test:e2e`): **10/10 passed**, with no console errors, CSP violations or off-origin requests.

Operational status: the **local scanner is operational in production**. Reputation lookup and AI analysis are deployed but **not configured**, so they are not operational.
