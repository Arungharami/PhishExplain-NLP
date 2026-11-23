# Roadmap

Ordered by the execution priorities. ✅ done · 🟡 partially done · ⬜ not started.

## P0 — Usable product ✅
✅ Repair the broken Shield page (`/shield.js`, `/shield.css` were missing) · ✅ local engine wired to UI · ✅ paste, raw message and `.eml`/`.txt` input · ✅ grounded findings with explanations and next steps · ✅ JSON/CSV/HTML/print exports · ✅ tests · ✅ deployment

## P1 — Detection quality 🟡
✅ postal-mime MIME parsing · ✅ safe HTML URL inspection · ✅ sender/header analysis · ✅ PSL-based domain logic · ✅ negation/quotation safeguards · ✅ expanded tests
⬜ Defanged URLs, `<img>`/CSS URLs, QR codes · ⬜ multilingual cues · ⬜ larger, data-driven brand list · ⬜ fuzz/ReDoS testing

## P2 — Intelligence 🟡
✅ Protected, rate-limited reputation adapter (GSB v5, URLhaus, VirusTotal) · ✅ protected AI analysis with grounding · ✅ honest unavailable states
⬜ Configure provider keys and durable limiter in Vercel (owner action) · ⬜ live provider smoke tests · ⬜ cost dashboard / alerts · ⬜ switch to Google Web Risk + licensed VirusTotal before any commercial use · ⬜ privacy-preserving `hashes.search` for GSB

## P3 — Product infrastructure 🟡
✅ Consent-based local history, workflow states, analyst notes, retention, delete-all (browser only)
⬜ Choose managed auth (e.g. Clerk, Auth0, Supabase Auth) · ⬜ encrypted server storage with retention policy · ⬜ RBAC and tenant isolation · ⬜ account deletion · ⬜ audit trail

## P4 — Integrations ⬜
⬜ Gmail read-only (requires Google restricted-scope verification) · ⬜ Microsoft Graph `Mail.Read` · ⬜ organization workspaces · ⬜ operational monitoring

## P5 — Validation & release 🟡
✅ Security regression tests · ✅ deployment smoke tests · ✅ automated keyboard/mobile checks
⬜ Permissioned, representative benchmark and published FPR/FNR/precision/recall · ⬜ external security review / pentest · ⬜ formal accessibility audit (contrast, NVDA/VoiceOver) · ⬜ legal/privacy review

## Engineering
⬜ TypeScript (start with JSDoc `@ts-check` on `shield/core`) · ⬜ provider integration tests in a gated CI job
