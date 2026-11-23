# Product architecture — PhishExplain Shield

PhishExplain Shield is a static, framework-free frontend plus three Vercel Node functions. The analysis engine is a set of plain ES modules that run **unchanged in the browser and in Node tests**, so there is one implementation of every check.

## Decision: no framework migration

The existing site (research portal + nine routes) is plain HTML/ES modules on Vercel with `cleanUrls`. A Next.js migration would have touched every research URL and added a build step without changing what the product can do. We kept the lightweight stack and added:

- a **page generator** (`scripts/pages.mjs`) so the eight product pages share one shell (header, two-area navigation, footer) without hand-copied markup;
- **vendored single-file ESM builds** of third-party libraries (`scripts/vendor.mjs` → `vendor/`), so browsers can import them without a bundler and Vercel needs no build step.

TypeScript was not introduced. Reliability comes instead from a strict report validator (`validateReport`), schema-constrained server I/O, and 80+ automated tests. Migrating `shield/core` to TypeScript (with JSDoc types as a stepping stone) is a roadmap item.

## Layout

```
index.html                 Product homepage (generated)
security/**/index.html     Shield pages (generated): scanner, dashboard, links, headers, analysis, reports, settings
shield.js / shield.css     Browser entry point (loads the page module) and design system
shield/core/               Analysis engine — shared by browser and Node
  parse.js                 MIME/RFC 5322 parsing via postal-mime; attachment metadata + magic bytes
  urls.js                  URL extraction (text + HTML anchors/forms) and structural inspection
  domains.js               Public Suffix List (tldts), registrable domains, look-alike + confusables
  sender.js                From / Reply-To / Return-Path / display-name checks
  headers.js               Received hops, Authentication-Results claims (unverified), alignment
  attachments.js           Extension, double-extension, RTLO, macro, HTML, signature mismatch
  language.js              Social-engineering cues with negation/quotation/awareness safeguards
  rules.js                 Rule catalog: title, basis, priority, weight, why, false positives, action
  score.js                 Deterministic, capped, UNCALIBRATED attention index
  guidance.js              Evidence-driven next steps + education glossary
  analyze.js               Orchestrator → report schema "phishexplain-shield-report/1" + validator
  report.js                JSON / CSV (formula-safe) / standalone HTML exports
  text.js                  Entity decoding, HTML→text, punycode decode, edit distance
shield/ui/                 Browser-only UI (DOM helpers, storage, rendering, one module per page)
api/reputation.js          Optional URL reputation (consent + access key + rate limits)
api/ai-analysis.js         Optional AI contextual analysis (consent + access key + rate limits)
api/infer.js               CAP 6640 research transformer endpoint (unchanged)
lib/                       Server helpers: http.js, ratelimit.js, reputation.js, ai.js, spans.js (research)
vendor/                    postal-mime 4.2.1 (MIT-0), tldts 7.5.5 (MIT) + manifest with SHA-256
nlp/ lab/ annotation/ …    Research Lab pages (preserved; /nlp/ is the former homepage)
engine.js platform.js app.js  Research extractor and workbench (unchanged; frozen for evaluation)
```

## Data flow

1. **Input** — paste (string) or file (`.eml` read as `ArrayBuffer`, `.txt` as text). Limit 5 MB.
2. **Parse** — `looksLikeRawMessage` decides whether a header block exists; raw messages go through postal-mime, others are treated as body text (HTML detected and converted to inert text).
3. **Inspect** — sender, headers, links (text part, HTML anchors/forms, visible text of HTML), attachments and language run independently and each return *findings* built from the rule catalog.
4. **Combine** — combination rules (pressure + sensitive request, credential + risky link) are added; findings are sorted and given stable ids (`F01-link.text-mismatch`).
5. **Score** — the attention index sums weights with per-category caps.
6. **Report** — the report object contains findings, links, sender, header claims, attachments, language spans, recommendations, checks performed/not performed, and limitations. The **full message body is not part of the report**; a separate `context` object (analyzed text for highlighting) stays in the browser tab's `sessionStorage`.

## Three kinds of information (never interchangeable)

| Kind | Where it comes from | How it is shown |
|---|---|---|
| Observed indicators (`basis: "observed"`) | Facts read from the message structure | Tier 1, teal |
| Heuristic interpretation (`basis: "heuristic"`, attention index) | Documented rules about wording/resemblance | Tier 2, amber, with false-positive notes |
| Verified external intelligence | Results actually returned by a configured provider | Tier 3, red only for `listed`/`flagged`, with provider + timestamp |
| AI judgments (`basis: "model_judgment"`) | Optional model output, grounded by exact quotes | Separate purple tier |

## Report schema (summary)

`schema`, `report_id` (`PXS-YYYYMMDD-XXXXXXXXXX`), `created_at`, `engine{name,version,language_ruleset,libraries}`, `input{source,kind,file_name,size_bytes,mime_parsed,warnings}`, `message`, `sender`, `headers{received[],authentication{verified:false,…},alignment}`, `links[]`, `attachments[]` (`malware_scanned:false`), `language{spans[]}`, `findings[]`, `observed_summary`, `attention`, `intelligence`, `ai_analysis`, `recommendations[]`, `checks`, `limitations`. Enforced by `validateReport()`.

Each finding: `id, rule, category, basis, title, evidence, source, excerpt, domain, url, details, priority (high|medium|low|info), points, why, false_positive_notes, next_action, context_flags[]`.

## Regenerating assets

```bash
npm run pages     # after editing scripts/pages.mjs
npm run vendor    # after upgrading postal-mime or tldts (then commit vendor/)
npm run check     # CI fails if either is stale
```
