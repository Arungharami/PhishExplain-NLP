# Known limitations

## Detection

- **Not benchmarked.** No false-positive rate, false-negative rate, precision or recall has been measured on representative email. The attention index weights are expert-chosen and uncalibrated.
- **Absence of indicators ≠ safe.** Business email compromise often contains no link, attachment or unusual wording. Image-only messages and text in attachments are not analyzed.
- **English-only language rules.** Paraphrases, misspellings and other languages are missed.
- **Limited brand list** (~37 organizations) for look-alike detection; similar-name legitimate businesses can be flagged (`same-name-different-suffix` is medium priority for that reason).
- **Context safeguards are heuristic.** Negation and quotation detection looks within the same sentence/line; it can both miss and over-apply.
- **URL extraction** covers `http(s)://` and `www.` in text and `<a>`, `<area>`, `<form>` in HTML. It does not cover URLs in CSS, `<img>`, QR codes, PDFs or Office documents, or defanged forms (`hxxp`).
- **No redirect resolution.** Shortener destinations stay unknown by design.

## Trust & verification

- SPF/DKIM/DMARC are never verified; pasted results are claims.
- Attachments are not scanned for malware.
- Reputation results reflect provider lists at lookup time only; providers are not configured on the deployment yet.

## Product

- No accounts, cloud history, teams or organizations. History is per-browser `localStorage` (not encrypted by Shield).
- No Gmail/Outlook integration; no continuous protection, blocking or quarantine.
- PDF export uses the browser print dialog rather than a generated PDF file.
- Without a durable rate-limit store, limits are per serverless instance.
- The access key is a single shared secret.

## Engineering

- Not migrated to TypeScript; types are enforced by validators and tests.
- No fuzzing; regex performance on adversarial input is bounded by size limits but not stress-tested.
- Accessibility: keyboard and responsive behavior are tested; color contrast and screen readers have not been formally audited.
