# Security model

This document lists the security controls that are **implemented and tested**. Anything not listed here should be assumed absent. See `THREAT_MODEL.md` for the threats these controls address and the remaining gaps.

## Untrusted content handling (browser)

| Control | Implementation | Test |
|---|---|---|
| Email HTML is never rendered | HTML parts are processed as strings (`htmlToText`, regex link extraction). No `DOMParser`, iframe or `innerHTML`. | `shield-routes`: UI code contains no `innerHTML`/`insertAdjacentHTML`/`document.write`; e2e hostile email creates no `<img>`/`<script>` |
| Text-only DOM insertion | `shield/ui/dom.js` builds nodes with `textContent`/text nodes. Live `href`s only for same-site paths and three provider reference domains (`safeHref`). | e2e "hostile HTML email" |
| Links are never visited | URLs are parsed with the WHATWG `URL` class and tldts only. No fetch, DNS or redirect following. | core URL tests; e2e asserts no off-origin requests |
| Attachments are never executed | Only filename, declared type, size and first 8 bytes are read. | attachment tests (`malware_scanned:false`) |
| Strict Content-Security-Policy | `/` and `/security/*`: `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. No inline scripts/styles/handlers in generated pages. | `shield-routes` CSP tests; e2e runs with the CSP enforced and fails on violations |
| Clickjacking | `X-Frame-Options: DENY` + `frame-ancestors 'none'` | `vercel.json` test |
| Exported HTML reports | All values escaped; report carries its own CSP meta (`default-src 'none'`), no scripts or external resources | XSS export test |
| CSV formula injection | Cells beginning with `= + - @ TAB CR` are prefixed with `'` | CSV test |
| No third-party requests | System fonts; no analytics, CDNs or trackers on Shield pages | e2e off-origin request check |

## Server endpoints (`/api/reputation`, `/api/ai-analysis`)

| Control | Implementation |
|---|---|
| Opt-in only | Both endpoints return `503 unavailable` unless explicitly configured. The local scanner never depends on them. |
| Authentication | `x-shield-key` header compared to `SHIELD_ACCESS_KEY` in constant time (SHA-256 + `timingSafeEqual`); keys shorter than 16 characters are refused. |
| Consent | Request body must contain `consent: true`; the UI requires a checkbox. |
| Same-origin | Requests with an `Origin` header from another host are rejected (403). |
| Input validation | JSON only (415 otherwise), byte limits (24 KB / 64 KB → 413), field allow-list, URL count ≤ 10, text ≤ 12,000 chars. |
| Rate limiting & budgets | Fixed-window counters per client/key and global daily caps. Durable via Upstash/Vercel KV when configured; per-instance memory otherwise (reported as `durable_rate_limit: false`). Store errors **fail closed** (429). Public reputation access is only possible with a durable limiter. |
| SSRF prevention | User URLs are never fetched. All outbound requests go through `providerFetch`, which only allows `https://safebrowsing.googleapis.com`, `https://urlhaus-api.abuse.ch`, `https://www.virustotal.com` (and `https://api.openai.com` in `lib/ai.js`), with `redirect: "error"` and timeouts. Private/local/single-label hosts are not even sent to providers. Credentials and fragments are stripped. |
| Prompt injection | Email wrapped in a random per-request boundary, system prompt declares it untrusted data, JSON-schema-constrained output (`strict: true`), and **every quote must be an exact substring** of the submitted text — anything else is discarded and counted (`rejected_ungrounded`). The model is asked for signals, never a verdict. |
| Secret handling | Secrets exist only in Vercel environment variables. `GET` status responses expose booleans, never values. Reports are passed through `scrubSecrets`. The browser keeps the access key in `sessionStorage` only. A test scans the repository for key patterns. |
| Logging | Server logs contain counts, latency, provider names and token usage — never message text or URLs. |
| Caching | API responses `Cache-Control: no-store`. Reputation results cached in instance memory, keyed by SHA-256 of the URL, honoring provider TTLs. |

## Authentication-result trust boundary

Shield never reports SPF, DKIM or DMARC as verified. Values from pasted `Authentication-Results` / `Received-SPF` headers are labeled **unverified claim (claimed by `<authserv-id>`)**. Claimed passes never lower the attention index (tested). A verified feature would require retrieving the message from the user's mailbox through an authenticated provider API and trusting only the top-most results added by that provider's own `authserv-id` (RFC 8601 §5) — not implemented.

## What is NOT in place

- No user accounts, so no per-user authorization, RBAC or tenant isolation (there is no server-side user data to isolate).
- The access key is a single shared secret, not per-user credentials.
- No WAF, bot protection or abuse monitoring beyond rate limits.
- No independent penetration test or security review has been performed.
