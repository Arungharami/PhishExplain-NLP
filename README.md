# PhishExplain-NLP v2 — Explainable phishing-related language extraction

**Production:** https://phishexplain-nlp.vercel.app

**Source:** https://github.com/Arungharami/PhishExplain-NLP

**CAP 6640 Natural Language Processing • Fall 2026 • Florida Atlantic University • final due December 4, 2026**

The project compares a classical regex/keyword information extractor with a prompted transformer extractor on three observable email-language categories: URL mentions, recipient-directed urgency, and actual requests for credentials. **It is not a phishing classification service.**

## Implemented now

- Existing responsive research landing page and browser-only lexical analysis workbench.
- Nine dedicated routes: /lab/, /dataset/, /annotation/, /evaluation/, /errors/, /research/, /methods/, /course/, /presentation/.
- Researcher-authenticated Vercel /api/infer endpoint connecting to the OpenAI Chat Completions API when configured; span validation and no public inference access.
- Same-input live comparison, span highlights, actual JSON export, and disagreement view; transformer success shown only after a real run.
- Dataset explorer for 60 unreviewed AI-assisted synthetic candidate emails.
- Browser-local human annotation studio: exact selection offsets, reviewer confirmation, rationale, import/export and draft progress.
- Frozen 20 calibration / 40 held-out split plan documented in data/split_manifest.json.
- Evidence import, exact span-and-label scoring, and genuine error-case inspection (blocked until reviewed data and model outputs exist).
- Transparent CAP 6640 submission audit and research resource pages.
- Shared metric module, unit tests and automated GitHub verification.

## Not completed / non-automatable

- **Real transformer inference has not run**: no OPENAI_API_KEY or researcher access secret is configured in Vercel.
- **Human gold labels are not complete**: author must personally read/approve annotations for at least 30 examples, preferably all 60.
- No verified two-method benchmark metric, statistical comparison, or authored six-error analysis exists yet.
- Final executive memo PDF (5–10 pages) and completed evidence XLSX require actual results and author reflection.
- Confirm a changed topic with the instructor if necessary.

## Running locally

Use a static HTTP server rather than file:// to load browser ES modules:

    python3 -m http.server 4173

Then open http://localhost:4173. A standalone Python static server does not implement /api/infer; use Vercel development tooling for the server function.

Node 20+:

    npm test
    npm run check

## Research and configuration

- docs/EXPERIMENT_PROTOCOL.md
- docs/ANNOTATION_GUIDE.md
- docs/DATASET_CARD.md
- docs/LLM_PROMPT.md
- docs/LLM_SETUP.md
- docs/REPRODUCIBILITY.md
- docs/SUBMISSION_CHECKLIST.md
- data/split_manifest.json

Read docs/LLM_SETUP.md for setting the protected Vercel environment. API secrets must never be put in client code or committed.

## Academic integrity

The corpus is synthetic/AI-assisted, not independently labeled. Scenario families are challenge-set design metadata, NOT human gold annotations. The author must personally verify gold text spans, record model identities and prompts, score frozen held-out results, explain six actual errors, verify academic sources, and write the half-page first-person reflection. Never substitute the website for the graded memo and spreadsheet.

No FAU or outside security authority endorsement is claimed.
