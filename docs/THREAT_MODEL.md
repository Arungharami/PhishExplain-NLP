# Threat model

Scope: the deployed Shield web application (static pages + `/api/reputation` + `/api/ai-analysis`) as of engine 1.0.0. Method: STRIDE-style enumeration per asset and entry point.

## Assets

1. Message content the user analyzes (may contain personal data).
2. Server secrets: provider API keys, `SHIELD_ACCESS_KEY`, OpenAI key, rate-limit store token.
3. Provider quotas and AI spend.
4. Integrity of the analysis (users act on it).
5. Locally saved history (sender addresses, subjects, URLs, evidence excerpts).

## Adversaries

- **A1 — Email author** (the phisher): controls every byte of the analyzed message, including headers, HTML, filenames and text aimed at the AI model.
- **A2 — Anonymous internet user**: calls the APIs directly, tries to exhaust quotas or reach internal networks.
- **A3 — Holder of a leaked access key.**
- **A4 — Local attacker with access to the user's browser profile.**

## Threats and mitigations

| # | Threat | Adversary | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | XSS via message HTML, subject, display name or filename | A1 | No HTML rendering; text-only DOM; strict CSP; escaped exports | Low. Regression-tested. |
| T2 | Drive-by via links/attachments | A1 | Nothing is fetched, opened or executed | Low. User may still click a link elsewhere. |
| T3 | Evading detection (paraphrase, images-only text, new domains, clean BEC) | A1 | Multiple independent checks; explicit "absence ≠ safety" messaging | **High** — heuristic detection is inherently evadable; not benchmarked. |
| T4 | Forged authentication headers to appear legitimate | A1 | Claims are labeled unverified and never reduce the index | Medium — users may still over-trust "pass". |
| T5 | Prompt injection into AI analysis | A1 | Boundary, untrusted-data instruction, schema output, exact-quote grounding, no tools, no verdicts | Medium — the model's *explanations* could still be skewed; they are labeled as model judgments. |
| T6 | Catastrophic regex backtracking (ReDoS) / huge inputs | A1 | Input cap 5 MB, per-part analysis window 200k chars, bounded regex quantifiers on HTML | Medium — not fuzz-tested; see roadmap. |
| T7 | SSRF via reputation endpoint | A2 | Allow-listed provider origins, `redirect: "error"`, private hosts refused, user URL never fetched | Low. |
| T8 | Quota/cost exhaustion | A2, A3 | Access key, per-client + global daily limits, fail-closed limiter | Medium without durable limiter (per-instance counters). Configure Upstash. |
| T9 | Secret leakage | A2 | Env-only secrets; status endpoints return booleans; repo scan test; logs exclude content | Low. |
| T10 | Cross-site request abuse of APIs | A2 | Same-origin check, JSON content type required, custom header required | Low. |
| T11 | Privacy leakage to providers | — | Consent gate; credentials/fragments stripped; private hosts not sent; disclosure of provider terms | Medium — GSB `urls:search` and VirusTotal receive full URLs by design. |
| T12 | Exposure of local history | A4 | History off by default; retention purge; delete-all; minimal content (no body) | Medium — localStorage is not encrypted. |
| T13 | Spreadsheet formula injection in CSV | A1 | Prefix neutralization | Low. |
| T14 | Misinterpreting the index as a probability/verdict | — | Labels, disclaimers on every surface, "uncalibrated" in schema | Medium — UX risk remains. |

## Out of scope / not yet modeled

Accounts, multi-tenant storage and mailbox OAuth do not exist. Before adding them, extend this model with: session hijacking, IDOR / cross-tenant access, OAuth token theft and scope abuse, data retention and lawful-access requests.
