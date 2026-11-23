#!/usr/bin/env node
/**
 * Evaluates manually reviewed, frozen information-extraction predictions.
 * No results are bundled or fabricated by this script.
 *
 * node scripts/evaluate.mjs path/to/frozen-evaluation.json
 * JSON shape:
 * { "examples": [
 *   { "id":"PNE-001", "text":"...", "review_status":"REVIEWED",
 *     "gold_spans":[{"category":"url","text":"...","start":0,"end":7}],
 *     "baseline_spans":[...], "transformer_spans":[...] }
 * ] }
 */
import { readFileSync } from "node:fs";

const CATEGORIES = ["url", "urgency", "credential"];

function validateSpans(row, spans, field) {
  if (!Array.isArray(spans)) throw new Error(row.id + ": " + field + " must be an array");
  const keys = new Set();
  for (const span of spans) {
    if (!CATEGORIES.includes(span.category)) throw new Error(row.id + ": unknown category in " + field);
    if (!Number.isSafeInteger(span.start) || !Number.isSafeInteger(span.end) || span.start < 0 || span.end <= span.start || span.end > row.text.length) {
      throw new Error(row.id + ": invalid offsets in " + field);
    }
    if (typeof span.text === "string" && row.text.slice(span.start, span.end) !== span.text) {
      throw new Error(row.id + ": text/offset mismatch in " + field);
    }
    const key = [span.category, span.start, span.end].join(":");
    if (keys.has(key)) throw new Error(row.id + ": duplicate span in " + field);
    keys.add(key);
  }
}

function counts(rows, method, category = null) {
  let tp = 0, fp = 0, fn = 0, correctEmails = 0;
  for (const row of rows) {
    const filter = spans => spans.filter(s => category === null || s.category === category);
    const gold = new Set(filter(row.gold_spans).map(s => [s.category,s.start,s.end].join(":")));
    const pred = new Set(filter(row[method]).map(s => [s.category,s.start,s.end].join(":")));
    let exact = gold.size === pred.size;
    for (const key of pred) {
      if (gold.has(key)) tp++;
      else { fp++; exact = false; }
    }
    for (const key of gold) {
      if (!pred.has(key)) { fn++; exact = false; }
    }
    if (exact) correctEmails++;
  }
  const precision = tp+fp ? tp/(tp+fp) : 0;
  const recall = tp+fn ? tp/(tp+fn) : 0;
  const f1 = precision+recall ? (2*precision*recall)/(precision+recall) : 0;
  return {tp,fp,fn,precision,recall,f1,perfect_emails:correctEmails};
}

function report(rows, method) {
  const perCategory = Object.fromEntries(CATEGORIES.map(c=>[c,counts(rows,method,c)]));
  const macroF1 = CATEGORIES.reduce((acc,c)=>acc+perCategory[c].f1,0)/CATEGORIES.length;
  return { micro:counts(rows,method), macro_f1:macroF1, per_category:perCategory };
}

function main() {
  if (process.argv.length !== 3) {
    console.error("Usage: node scripts/evaluate.mjs <human-reviewed-frozen-evaluation.json>");
    process.exit(1);
  }
  const data = JSON.parse(readFileSync(process.argv[2], "utf8"));
  const rows = data.examples;
  if (!Array.isArray(rows) || rows.length === 0) throw new Error("JSON needs a nonempty examples array");
  const ids = new Set();
  for (const row of rows) {
    if (typeof row.id !== "string" || ids.has(row.id)) throw new Error("Missing/duplicate example ID");
    ids.add(row.id);
    if (typeof row.text !== "string") throw new Error(row.id + ": missing text");
    if (row.review_status !== "REVIEWED") throw new Error(row.id + ": not human-reviewed; refusing to score");
    for (const field of ["gold_spans","baseline_spans","transformer_spans"]) validateSpans(row,row[field],field);
  }
  const output = {
    evaluation_status:"COMPUTED_FROM_PROVIDED_REVIEWED_DATA",
    n_reviewed_examples:rows.length,
    zero_division:"zero",
    metric:"exact category-and-offset span match",
    baseline:report(rows,"baseline_spans"),
    transformer:report(rows,"transformer_spans"),
    note:"These scores only describe the supplied verified evaluation file; save its hash, protocol, model settings and full per-example output before making any research claim."
  };
  console.log(JSON.stringify(output,null,2));
}
main();
