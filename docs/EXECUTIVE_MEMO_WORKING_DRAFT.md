# PhishExplain-NLP — Executive Memo WORKING DRAFT (NOT SUBMISSION READY)

**CAP 6640 — Natural Language Processing | Fall 2026**  
**Arun Kumar Gharami | Florida Atlantic University**  
**Working draft:** November 23, 2026

> RESEARCH INTEGRITY NOTICE: The research design, code, candidate data and a protected inference endpoint exist. Human gold annotations, actual transformer test outputs, six error analyses, final numerical results, and first-person reflection are NOT complete. Do not submit this document as a finished experiment or present unfilled sections as observations.

## 1. Problem and motivation

Phishing emails frequently combine visible URLs, language that encourages hurried action, and requests for authentication secrets. Identifying these observable cues is useful for explaining a message to a human reader, but it is a different NLP problem from identifying whether the entire email is malicious. A URL can occur in a routine course announcement, a password warning may quote a prohibited action, and a deadline can be ordinary rather than coercive. A simple extractor must therefore support both positive evidence and legitimate negative cases.

This project asks whether an interpretable classical NLP rule system and a contextual transformer can extract the same three cue families from identical email texts. The desired output is a set of exact character spans, rather than a binary phishing verdict. The focus is transparency: every prediction should be grounded in the actual text, scored against human-reviewed gold spans, and associated with a specific error mechanism when wrong.

## 2. Literature review

Atawneh and Aljehani [2] investigate phishing classification using deep-learning architectures including BERT and LSTM. Their work demonstrates the relevance of sequence representation in phishing detection, but its primary prediction target is a message-level class. Their published classification scores should not be used as a substitute for span extraction results.

Uddin and Sarker [3] report an explainable transformer-based phishing classification approach with DistilBERT and attribution methods. Such attribution can show tokens contributing to a class prediction, but token importance is not equivalent to returning an exact credential-request span. This distinction motivates direct span annotation in the present study.

Tooher and Lallie [1] build a two-stage persuasion-based pipeline: a DistilBERT model detects persuasion principles and a subsequent component predicts phishing status. This domain-specific system offers a valuable comparison for interpreting pressure-related language. Nevertheless, their principle labels and email-level decision process differ from this project's three extraction categories and exact-boundary scoring.

Sentence-BERT [4] illustrates how transformer representations can encode context. Although embeddings are not the executed main approach here, the work clarifies why semantically related phrases may have different behavior under surface-form rules versus contextual models. Søgaard and colleagues [5] caution that evaluation splits shape the meaning of model performance. This project therefore separates a calibration set used for rule and prompt development from a locked evaluation set. NIST's Trustworthy Email guidance [6] provides security context but is not used as an experimental NLP baseline.

The gap addressed here is narrowly scoped, auditable extraction of linguistic cues, not another claim of superior phishing classification accuracy. The corpus is small and synthetic by design, so any results should be interpreted as a teaching-scale experimental case study.

## 3. Domain-specific technologies

The two-stage persuasion-based classifier of Tooher and Lallie [1] is a relevant domain-focused NLP technology beyond the present course comparison. Its DistilBERT layer produces persuasion-principle predictions that can support a phishing decision. PhishExplain-NLP instead attempts direct localization of three defined cue categories, without requiring a phishing class label. Both systems use linguistic evidence, but target different units of annotation and metrics. The present report does not claim to reproduce, improve, or outperform the referenced domain system.

## 4. Approaches and experimental protocol

### 4.1 Data and human gold annotations

The candidate collection contains 60 synthetic email texts generated with AI assistance. Each belongs to one of five design families: direct credential request, urgency without credentials, neutral URL mention, quoted or negated hard negative, and ordinary no-cue message. These family tags are not ground truth. The split is frozen deterministically by example ID: 20 calibration and 40 held-out examples, balanced four and eight per family respectively. The full contents and split manifest are included in the public source repository.

The researcher must personally examine the source text, determine positive and negative cases, choose exact [start,end) UTF-16 offsets, and write rationale where interpretation is ambiguous. A model's answer is never accepted as gold automatically. Only human-confirmed records are eligible for the final test comparison. Personal, confidential, and customer emails are prohibited.

### 4.2 Method A: lexical baseline

The existing lexical engine identifies explicit HTTP(S) URLs using a regular expression, urgency patterns from a fixed phrase inventory, and credential request patterns using a verb-plus-secret lexicon. It returns a category, literal substring, source offsets, and triggering rule. Its benefits include traceable behavior, low execution cost, and reproducibility. Its limitations include paraphrase brittleness, quotation and negation mistakes, and cases where the real cue is implicit.

### 4.3 Method B: prompted transformer

The transformer method is specified as a versioned system prompt with a grounded JSON output contract. It must operate on the same input and return category and exact source spans. The Vercel endpoint validates categories, offsets, source substrings, and maximum input size. It rejects malformed or unsupported spans rather than silently converting them to valid predictions. Researcher authorization protects the paid endpoint.

**Current status: inference has NOT run.** Once a provider key and separate researcher authorization key are configured, model identity, prompt version, settings, execution timestamp, original response, validation failures, and latency should be recorded. No model-quality claim is justified without this evidence.

### 4.4 Measurement

The primary metric is exact span-and-label micro-F1. A predicted span is a true positive only if its category and start/end boundaries match an unmatched gold span in the same email. Remaining predicted spans count as false positives; remaining gold spans count as false negatives. Precision and recall are computed from aggregate TP, FP and FN over the 40 held-out emails. The macro-average across three categories and per-label figures are secondary diagnostics. Each method must use the same test texts and annotations. Calibration data must not be scored as held-out data.

## 5. Results — REQUIRED REAL DATA

**Not yet evaluated.** No human-reviewed final test dataset or actual transformer outputs are present.

Insert verified table here after running the frozen experiment:

| Method | Precision | Recall | Exact-span micro-F1 | Macro-F1 |
| --- | --- | --- | --- | --- |
| Rules | PENDING | PENDING | PENDING | PENDING |
| Transformer | PENDING | PENDING | PENDING | PENDING |

The observed results should be linked to a saved experiment manifest, source checksum, model/prompt settings, and per-example predictions. Do not include artificially selected demonstration examples in place of measured comparisons.

## 6. Error analysis — SIX AUTHENTIC CASES REQUIRED

**Unfinished.** Following held-out scoring, select three actual baseline errors and three actual transformer errors. For each, include the specific example ID, gold span, observed prediction, error category, and a first-person explanation grounded in an NLP concept. Potential categories to inspect (not yet observed errors) include negation scope, quoted examples, ambiguity, pattern brittleness, semantic paraphrase, and ungrounded generations.

## 7. Recommendation, risks and limitations

A prudent deployment recommendation must depend on observed results and available operational controls. The lexical baseline has an inspectable decision procedure and can run locally without transmitting email text. A prompted transformer may interpret contextual language missed by rigid patterns, but introduces provider costs, latency, and risk of unsupported or unstable extraction. Neither approach establishes sender reputation, web destination safety, or actual malicious intent.

Synthetic examples provide controlled challenge cases but may not represent real traffic distributions. The single-reviewer annotation protocol invites subjectivity. Test results on 40 messages will have substantial sampling uncertainty. Prompt design and lexicon adjustment must be confined to calibration examples; otherwise the reported test comparison is biased. Privacy requires avoiding real inbox integrations, confidential messages and actual credentials.

## 8. Half-page first-person reflection — AUTHOR MUST WRITE/VERIFY

**Not authored.** The researcher should personally describe: what surprised them after reviewing concrete examples and real errors, what they would change in a second experiment, what programming/visual design assistance AI provided, which annotations and decisions were completed personally, and what limitations remain. Do not automatically invent this personal reflection.

## 9. References

Use verified bibliography in docs/LITERATURE_VERIFIED.md (six currently identified sources, including more than three papers). Confirm every final citation and retain consistent IEEE-style numbering.

---

**Submission gate:** This working draft must not be converted to a final-ready PDF until experiment evidence, error cases, citation audit, and personal reflection are finished. The final PDF must be within the professor's 5–10 page range excluding references.
