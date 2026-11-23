# PhishExplain Shield

**Intelligent Email Threat Analysis. Clear Evidence. Safer Decisions.**

- **Production:** https://phishexplain-nlp.vercel.app
- **Source:** https://github.com/Arungharami/PhishExplain-NLP
- **Product owner:** Arun Kumar Gharami
- **Research:** CAP 6640 Natural Language Processing, Florida Atlantic University (Fall 2026)

The repository holds two clearly separated areas that share one visual system:

| Area | What it is | Routes |
|---|---|---|
| **PhishExplain Shield** (public beta) | A usable email threat analysis tool. Paste or import an email and see grounded sender, link, attachment, header and social-engineering indicators with explanations and safer next steps. | `/`, `/security/`, `/security/dashboard/`, `/security/links/`, `/security/headers/`, `/security/analysis/`, `/security/reports/`, `/security/settings/` |
| **NLP Research Lab** | The independent CAP 6640 study comparing a classical extractor with a prompted transformer against human-reviewed labels. | `/nlp/` (former homepage), `/lab/`, `/dataset/`, `/annotation/`, `/evaluation/`, `/errors/`, `/research/`, `/methods/`, `/course/`, `/presentation/` |

Research results are not used as evidence of Shield's detection performance. Shield's detection accuracy has **not** been measured yet.

## What Shield does today

- Parses pasted text, full raw messages and `.eml`/`.txt` files **in the browser** (postal-mime), with nothing uploaded.
- Inspects every link without visiting it: registered domain via the Public Suffix List, HTTP, IP and obfuscated-IP hosts, `@` userinfo tricks, punycode/IDN, shorteners, deep subdomains, ports, redirect parameters, `javascript:` links, HTML forms, link text that names a different domain, and brand look-alikes.
- Checks sender consistency (From / Reply-To / Return-Path, display-name tricks, free-mail impersonation, look-alike sender domains).
- Shows the Received route and SPF/DKIM/DMARC **as unverified claims**.
- Reads attachment metadata (double extensions, executables, macros, HTML/SVG, RTLO, content signature mismatch). No malware scanning.
- Detects urgency, account threats, credential and one-time-code requests, payment/BEC pressure and impersonation language, and does not weight negated, quoted or awareness-training text.
- Explains every finding: evidence, source, why it matters, how it could be legitimate, and the recommended action.
- Produces an **uncalibrated** heuristic attention index (not a probability, never a safety verdict).
- Exports JSON, CSV, a standalone HTML report, and PDF via print.
- Offers opt-in local history with workflow states and analyst notes (browser only).
- **Optional server features (off until configured):** URL reputation via Google Safe Browsing, URLhaus and VirusTotal, plus AI contextual analysis via OpenAI. Both require consent and an access key, are rate-limited, and never fetch user URLs.

Full status: [docs/PRODUCT_STATUS.md](docs/PRODUCT_STATUS.md) · Limits: [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md)

## Quick start (developers)

Requirements: Node.js 20+; Google Chrome or Microsoft Edge for the browser tests.

```bash
git clone https://github.com/Arungharami/PhishExplain-NLP.git
cd PhishExplain-NLP
npm ci
npm run dev          # http://127.0.0.1:4173 (static site + /api/* + production security headers)
npm test             # unit, security, route and research tests
npm run test:e2e     # real-browser integration tests
npm run check        # syntax, generated pages and vendored libraries up to date
```

No environment variables are needed for the scanner. To enable the optional features, copy the names from [.env.example](.env.example) into Vercel (or your shell for local API testing). Never commit real keys.

### Editing pages and libraries

- Product pages are generated from `scripts/pages.mjs`. Edit the generator and run `npm run pages`; don't edit the generated HTML by hand.
- `vendor/` holds bundled browser builds of postal-mime and tldts. After upgrading either package, run `npm run vendor` and commit.

## Documentation

| Document | Purpose |
|---|---|
| [PRODUCT_STATUS.md](docs/PRODUCT_STATUS.md) | Verified status of every capability, test results, blockers |
| [PRODUCT_ARCHITECTURE.md](docs/PRODUCT_ARCHITECTURE.md) | Modules, data flow, report schema |
| [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Implemented controls and how they are tested |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threats, mitigations, residual risk |
| [PRIVACY.md](docs/PRIVACY.md) | What data goes where, retention, user controls |
| [INTEGRATIONS.md](docs/INTEGRATIONS.md) | Reputation/AI adapters and the mailbox integration design |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Vercel setup, environment variables, release and rollback |
| [TESTING.md](docs/TESTING.md) | Test suites and known gaps |
| [ROADMAP.md](docs/ROADMAP.md) | P0–P5 progress |
| [KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) | What Shield cannot do |

**Status vocabulary:** *Implemented* → *Tested locally* → *Deployed* → *Configured* → *Operational* → *Externally validated*; *Planned* means not implemented.

## CAP 6640 research (unchanged)

The research compares a regex/keyword extractor (`engine.js`, frozen as the study baseline) with a prompted transformer (`api/infer.js`, researcher-key protected) on three observable cue categories (URL mentions, urgency, credential requests) using 60 AI-assisted synthetic candidates with a frozen 20/40 calibration/held-out split. **It is not a phishing classification service.** Human gold labels, the paired evaluation, the error analysis, the executive memo and the evidence spreadsheet remain the author's responsibility. See:

- docs/EXPERIMENT_PROTOCOL.md, docs/ANNOTATION_GUIDE.md, docs/DATASET_CARD.md, docs/LLM_PROMPT.md, docs/LLM_SETUP.md, docs/REPRODUCIBILITY.md, docs/SUBMISSION_CHECKLIST.md, docs/LITERATURE_VERIFIED.md, data/split_manifest.json
- Offline evaluator: `node scripts/evaluate.mjs <human-reviewed-frozen-evidence.json>` (refuses unreviewed data)

Shield shares parsing ideas with the research extractor, but it uses its own ruleset (`shield-lang-1`), so the research baseline stays reproducible.

## Disclaimer

PhishExplain Shield is a beta decision-support tool. It does not guarantee safety, does not verify sender authentication, does not scan attachments for malware, and does not protect an inbox. No FAU or external security-authority endorsement is claimed.
