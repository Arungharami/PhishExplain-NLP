# Privacy

**Summary:** the Shield scanner runs in your browser. Message content is not uploaded unless you explicitly request an AI analysis. Nothing is stored unless you turn on local history.

## What happens to the data

| Action | What leaves your device | Recipient | Retention |
|---|---|---|---|
| Scan (paste or file) | Nothing | — | The analysis stays in this tab's `sessionStorage` until the tab closes |
| Save to history (opt-in) | Nothing | — | Browser `localStorage` until you delete it or the retention period (7/30/90 days, default 30) expires |
| Reputation lookup (opt-in, consent per request) | The selected URLs, with embedded user names/passwords and `#fragments` removed | Shield server → configured providers (Google Safe Browsing, URLhaus, VirusTotal) | Not stored by Shield beyond a short in-memory cache (provider TTL, max 24 h). Providers keep data under their own terms. |
| AI analysis (opt-in, consent per request) | The message body text (up to 12,000 characters) | Shield server → OpenAI | Not stored by Shield. OpenAI processes it under its API data-usage terms. |
| Export | Nothing — files are generated locally | — | Wherever you save them |

## What saved history contains

Report metadata (id, time, engine version), subject, sender/Reply-To/Return-Path addresses, URLs found, attachment names, header claims, findings with short evidence excerpts (about ±48 characters around a match), your workflow status and notes. **The full message body is not saved.**

## Server logs

Vercel function logs record: endpoint, number of URLs, providers used, failure counts, latency, and AI token usage. They never record message text, URLs or access keys. Rate-limit keys use a SHA-256 hash of the client IP.

## What is not collected

No accounts, cookies for tracking, analytics, advertising pixels, third-party fonts or CDNs on Shield pages.

## Your controls

- **Settings → Delete data** removes history, settings, the current analysis and the session key from the browser.
- Turning off local history deletes saved analyses.
- Clearing site data in your browser removes everything.

## Guidance for users

- Prefer synthetic messages or your own mail. Do not submit other people's private email unless you are authorized to do so (for example, as part of your organization's security process).
- Do not include passwords or one-time codes in pasted text.

## Third-party terms (verified 2026-11-23)

- Google Safe Browsing: non-commercial use only; `urls:search` sends full URLs to Google.
- VirusTotal public API: non-commercial use; Shield only performs lookups and never submits URLs.
- URLhaus: requires an abuse.ch Auth-Key; subject to abuse.ch terms.
- OpenAI API: see OpenAI's API data-usage policy for the deployment's account.

Operating Shield as a commercial or organizational service requires reviewing these terms and likely replacing Safe Browsing with Google Web Risk and the VirusTotal public API with a licensed tier.
