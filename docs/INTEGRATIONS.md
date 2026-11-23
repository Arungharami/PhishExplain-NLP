# Integrations

Status vocabulary (used across all docs): **Implemented** (code exists) → **Tested locally** (automated tests pass) → **Deployed** (in the production build) → **Configured** (credentials set in Vercel) → **Operational** (verified working in production) → **Externally validated** (independently evaluated). **Planned** = not implemented.

| Integration | Status | Notes |
|---|---|---|
| Google Safe Browsing v5 `urls:search` | Implemented, tested locally (mocked) | Not configured. Non-commercial only. |
| URLhaus API v1 `/url/` | Implemented, tested locally (mocked) | Not configured. Needs abuse.ch Auth-Key. |
| VirusTotal API v3 `GET /urls/{id}` | Implemented, tested locally (mocked) | Not configured. Lookup only; 404 → "no record". |
| OpenAI Chat Completions (structured outputs) for AI analysis | Implemented, tested locally (mocked) | Not configured. |
| Upstash Redis REST / Vercel KV rate limiting | Implemented, tested locally (mocked failure) | Not configured. |
| Gmail (read-only, user-selected messages) | Planned | See design below. |
| Microsoft 365 / Outlook via Microsoft Graph | Planned | See design below. |

No provider call has been executed against a live API from this codebase. "Implemented" does not mean operational.

## Reputation adapter

`lib/reputation.js` normalizes every provider into:

```json
{ "provider": "google_safe_browsing", "query_type": "url", "query": "https://…", "status": "listed | flagged | not_listed | no_record | unavailable | not_configured",
  "summary": "…", "provider_labels": ["SOCIAL_ENGINEERING"], "details": {…}, "checked_at": "ISO", "cache_age_seconds": 0, "reference": "provider page or null" }
```

- Only `listed` (GSB, URLhaus) and `flagged` (VirusTotal vendor verdicts > 0) are shown in red, always with the provider name and timestamp.
- `not_listed` is explicitly described as "no listing at lookup time — not a safety verdict".
- No score is ever substituted when a provider is unavailable.

To add a provider: add its origin to `PROVIDER_ORIGINS`, a checker returning `{ r, ttl }`, its env var to `configuredProviders`, a mocked test, and update this table and `.env.example`.

## AI analysis

`lib/ai.js` → OpenAI `/v1/chat/completions` with `response_format: json_schema (strict)`. Output categories: `credential_request, coercive_urgency, impersonation, payment_pressure, suspicious_combination, possible_false_positive`. Prompt version `shield-ai-1`. Every finding must quote the email verbatim; ungrounded output is discarded. The research endpoint `api/infer.js` is separate and unchanged.

## Planned: mailbox integrations (design only — not implemented)

Principles: explicit connect/disconnect, minimum scopes, **read-only**, user selects each message, no automatic delete/quarantine/move.

**Gmail** — OAuth 2.0 web flow; scope `https://www.googleapis.com/auth/gmail.readonly` (restricted scope → Google verification and a security assessment are required before public use). Fetch `users.messages.get?format=raw` for one selected message and run the same local engine. Because the message comes from the provider, the top-most `Authentication-Results` added by Google's own authserv-id could be presented as *provider-reported* authentication (still not independently verified by Shield).

**Microsoft Graph** — Microsoft identity platform auth code + PKCE; delegated `Mail.Read`. `GET /me/messages/{id}/$value` for MIME. Tenant admins may need to consent.

Prerequisites before building either: user accounts and sessions, encrypted token storage, token revocation on disconnect, audit log, privacy policy update, provider app verification, and tests for token handling and error paths.
