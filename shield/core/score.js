// Deterministic, UNCALIBRATED heuristic attention index.
// It orders messages for human review. It is NOT a probability of phishing, NOT a verdict,
// and a low value NEVER means a message is safe. Weights are documented in rules.js.
import { CATEGORY_CAPS } from "./rules.js";

export const ATTENTION_BANDS = Object.freeze([
  { min: 55, band: "high", label: "High attention", summary: "Several strong indicators were observed. Do not act on this message until it is independently verified." },
  { min: 25, band: "elevated", label: "Review recommended", summary: "Indicators were observed that deserve careful review before you click, reply, pay or sign in." },
  { min: 1, band: "low", label: "Low attention", summary: "Only minor indicators were observed. This does not mean the message is safe." },
  { min: 0, band: "none", label: "No listed indicators", summary: "None of Shield's checks matched. This does not mean the message is safe; many attacks contain no detectable indicators." }
]);

export function attentionIndex(findings) {
  const perCategory = {};
  const contributions = [];
  // Highest-weight findings first so category caps keep the most significant evidence.
  const ordered = [...findings].sort((a, b) => b.points - a.points || a.id.localeCompare(b.id));
  for (const f of ordered) {
    if (!f.points) continue;
    const cap = CATEGORY_CAPS[f.category] ?? 20;
    const used = perCategory[f.category] ?? 0;
    const add = Math.max(0, Math.min(f.points, cap - used));
    perCategory[f.category] = used + add;
    if (add > 0) contributions.push({ finding_id: f.id, rule: f.rule, points: add });
  }
  const raw = Object.values(perCategory).reduce((a, b) => a + b, 0);
  const index = Math.min(100, Math.round(raw));
  const band = ATTENTION_BANDS.find(b => index >= b.min);
  return {
    index,
    band: band.band,
    label: band.label,
    summary: band.summary,
    type: "uncalibrated_heuristic_attention_index",
    scale: "0-100 review priority; not a probability",
    category_points: perCategory,
    contributions,
    disclaimer: "This index ranks observed indicators for human attention using fixed weights. It has not been calibrated against a validated benchmark, it is not a probability that the message is phishing, and a low value is not evidence that the message is safe."
  };
}
