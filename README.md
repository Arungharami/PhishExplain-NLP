# PhishExplain-NLP

**Evidence-first phishing-language information extraction research portal**

**Live site:** https://phishexplain-nlp.vercel.app

**Course:** CAP 6640 Natural Language Processing (Fall 2026), Florida Atlantic University

**Researcher:** Arun Kumar Gharami

**Final deadline:** December 4, 2026

## Research question

How do transparent lexical rules and prompted transformer language models compare when extracting URL mentions, urgency/pressure language, and direct credential requests from email texts?

This is an **information extraction** experiment, NOT a production phishing detector. A visible URL is not necessarily malicious.

## Honest implementation status

| Capability | Status |
| --- | --- |
| Responsive portal, synthetic example workbench | Implemented |
| Browser-only rules and regex engine with exact source offsets | Implemented |
| JSON inspector / export | Implemented |
| Research protocol, evidence CSV template and annotation guide | Implemented |
| Browser baseline tests | Implemented |
| Transformer inference and saved predictions | Pending |
| Human-reviewed gold labels and held-out F1 scores | Pending |
| Final PDF memo and completed evidence workbook | Pending |

## Local use

ES modules require a local HTTP server rather than file:// URLs.

    python3 -m http.server 4173

Open http://localhost:4173.

Run Node.js 20+ tests:

    npm test

## Files

- index.html: main site and academic presentation
- styles.css: responsive visual design system
- app.js: browser interactions
- engine.js: local rule-based extractor
- tests/engine.test.mjs: deterministic baseline tests
- evidence-template.csv: one-row-per-example course evidence template
- docs/EXPERIMENT_PROTOCOL.md: study design and metrics
- docs/ANNOTATION_GUIDE.md: annotation definitions and hard negatives
- docs/LLM_PROMPT.md: proposed transformer prompt, not executed
- docs/MEMO_OUTLINE.md: executive memo structure

## Research ethics

Use only public or synthetic emails and redact any private content. Do not submit real credentials, account messages, or personal data. User text stays within the browser in the current workbench. External fonts may be requested, but pasted text is not transmitted.

The author must personally review at least 30 gold-labeled examples and explain three genuine errors per approach. Reproduce all reported numbers using frozen data and outputs; do not infer transformer performance from the demo. Disclose AI-assisted programming and writing in the required first-person reflection.

Independent coursework; no institutional or security authority endorsement is implied.
