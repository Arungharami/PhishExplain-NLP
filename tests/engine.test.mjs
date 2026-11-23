import test from "node:test";
import assert from "node:assert/strict";
import { extractSignals, SAMPLES, ENGINE_MAX_LENGTH } from "../engine.js";

test("account alert has URL, urgency, and credential cues", () => {
  const result = extractSignals(SAMPLES.account.text);
  assert.ok(result.counts.url >= 1);
  assert.ok(result.counts.urgency >= 1);
  assert.ok(result.counts.credential >= 1);
});
test("routine message has no extracted cues", () => {
  const result = extractSignals(SAMPLES.normal.text);
  assert.equal(result.total_matches, 0);
});
test("offsets resolve to original exact matched text", () => {
  for (const sample of Object.values(SAMPLES)) {
    const result = extractSignals(sample.text);
    for (const category of result.categories) {
      for (const match of category.matches) {
        assert.equal(sample.text.slice(match.start, match.end), match.text);
      }
    }
  }
});
test("hard negative demonstrates lexical false-positive limitation", () => {
  const result = extractSignals(SAMPLES.ambiguous.text);
  assert.ok(result.counts.credential >= 1);
});
test("input length bound prevents oversized analysis", () => {
  assert.throws(() => extractSignals("x".repeat(ENGINE_MAX_LENGTH + 1)), RangeError);
});
test("matching is deterministic", () => {
  const a = extractSignals(SAMPLES.delivery.text);
  const b = extractSignals(SAMPLES.delivery.text);
  assert.deepEqual(a,b);
});
