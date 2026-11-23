# PhishExplain-NLP experimental protocol (draft v0.1)

**Status:** Study plan, not observed results.

## Domain and task

Domain: cybersecurity email content. Course task: information extraction.

Research question: when do regex/keyword rules and a prompted transformer model agree or disagree on three kinds of observable evidence in email text?

This experiment does **not** classify an email as phishing or prove maliciousness of a URL.

## Data and split

Target 60+ public or synthetic email texts with an independent provenance column. Prefer a balanced selection of 20 calibration examples and 40 held-out examples. Manually review and gold-label all 60 if possible, exceeding the minimum of 30 human gold examples and 50 total examples. Never use real confidential emails.

Include explicit requests, paraphrases, implied pressure, quoted instructions, negation, benign links, legitimate administrative deadlines, and no-cue cases. Freeze examples and their hashes before evaluation. Do not tune on the held-out partition.

## Gold extraction labels

- URL: any HTTP(S) URL surface form. Label does not imply maliciousness.
- URGENCY: a message-directed pressure, threat or deadline. Exclude merely quoted examples and ordinary dates where possible.
- CREDENTIAL: direct or indirect request to submit, disclose, enter or verify a sign-in secret, password or one-time code. Do not count negated advice such as "do not share your password".

Use exact source-string spans with zero-based start and end-exclusive offsets, written and independently checked by the researcher. Record empty gold sets. Preserve rationale for ambiguous examples and verify every offset against the original text.

## Approach A: traditional NLP

Deterministic regex URL matching and keyword/phrase rules implemented in engine.js. Freeze lexicon version and record actual per-example predictions.

## Approach B: transformer

Use a fixed, versioned prompted LLM and structured JSON spans as described in docs/LLM_PROMPT.md. Record model/provider/version, timestamp, temperature, prompt, parser failures, exact outputs and settings. Validate evidence grounding. Transformer inference is not implemented in the website yet.

Optional bonus: an independently frozen third approach, subject to course approval.

## Primary scoring

Micro-averaged exact span-and-label F1 across the held-out messages. A predicted (email ID, label, start, end) quadruple is a true positive only if exactly matched to an unmatched gold quadruple. Unmatched predictions are false positives; unmatched gold spans are false negatives.

Precision = TP/(TP+FP). Recall = TP/(TP+FN). F1 = 2PR/(P+R). Document zero-denominator handling. Also report per-label metrics and cases with no gold spans. If using overlap F1 as a secondary metric, never substitute it for the preregistered exact-match metric.

If computing confidence intervals, resample **emails** in paired bootstrap, not individual correlated spans.

## Error analysis and interpretation

Select three actual errors per approach from held-out data, each grounded in its original message and gold annotation. Explain errors with ambiguity, negation scope, tokenization, lexical mismatch, semantic inference, or hallucinated spans. Avoid fabricated examples or numbers.

## Required course outputs

Executive PDF memo (5–10 pages, references excluded), evidence spreadsheet (every example with text, gold labels, both methods and metric computation), model prompts/settings or code, at least five actual cited references including three research papers, risks and a half-page first-person reflection on AI assistance and original human work.

## Limitations

Synthetic realism, annotation subjectivity, quoted language, domain shift, false confidence from URL matches, and prompt variability. Do not treat output as a mail security verdict.
