# Verified literature starting points (IEEE-style draft bibliography)

**Verification date:** 2026-11-23. Metadata and key topic boundaries checked against publisher/arXiv pages. The research author must open each source before final course submission. These papers are used for background, NOT as evidence of PhishExplain-NLP's own performance.

[1] P. Tooher and H. S. Lallie, "A Two-Stage Deep Learning Framework for AI-Driven Phishing Email Detection Based on Persuasion Principles," *Computers*, vol. 14, no. 12, art. 523, 2025. DOI: 10.3390/computers14120523. https://www.mdpi.com/2073-431X/14/12/523

Relevant: domain-specific DistilBERT persuasion-principle classification followed by phishing classification. This is different from exact evidence-span extraction. Provides a strong **domain technology** comparison.

[2] S. Atawneh and H. Aljehani, "Phishing Email Detection Model Using Deep Learning," *Electronics*, vol. 12, no. 20, art. 4261, 2023. DOI: 10.3390/electronics12204261. https://www.mdpi.com/2079-9292/12/20/4261

Relevant: demonstrates BERT and recurrent architectures for email-level phishing classification. Its published accuracy is not comparable with our exact-span micro-F1.

[3] M. A. Uddin and I. H. Sarker, "An Explainable Transformer-based Model for Phishing Email Detection: A Large Language Model Approach," arXiv:2402.13871, 2024. https://arxiv.org/abs/2402.13871

Relevant: uses an optimized fine-tuned DistilBERT classifier plus LIME and Transformer Interpret attributions. Word importance for classification is not equivalent to a grounded extracted request span.

[4] N. Reimers and I. Gurevych, "Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks," in *EMNLP-IJCNLP*, 2019. https://aclanthology.org/D19-1410/

Relevant: contextual sentence embeddings. Used here as background, not a claimed executed method.

[5] A. Søgaard et al., "We Need to Talk About Random Splits," in *EACL*, 2021. https://aclanthology.org/2021.eacl-main.156/

Relevant: motivates careful evaluation partitions. This project uses an authored frozen 20/40 split; the paper does not prove that split is representative.

[6] NIST, *Trustworthy Email*, SP 800-177. https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-177.pdf

Relevant: email security background, not an NLP experiment.

## Research gap and boundaries

These studies primarily target **whole-email classification** or persuasion labels. Our narrower experiment extracts localized, human-reviewable spans for URL mentions, urgency/pressure, and credential requests. A classifier's accuracy cannot be equated to an extraction F1. The prompted LLM remains unexecuted until configured. The synthetic dataset limits ecological validity.

## Final citation audit

Check the actual author lists, publication venues, dates, page ranges, and DOI links immediately before the final PDF. Do not import numerical claims from other papers as PhishExplain-NLP results. Disclose LLM or AI assistance with writing and code in the first-person reflection.
