// PhishExplain Shield — local analysis orchestrator.
// Produces a report in schema "phishexplain-shield-report/1". Runs identically in the browser and Node.
import { parseMessage, LIMITS } from "./parse.js";
import { analyzeSender } from "./sender.js";
import { analyzeHeaders } from "./headers.js";
import { collectLinks } from "./urls.js";
import { analyzeAttachments } from "./attachments.js";
import { analyzeLanguage, LANGUAGE_RULESET } from "./language.js";
import { attentionIndex } from "./score.js";
import { recommendations } from "./guidance.js";
import { makeFinding, PRIORITIES } from "./rules.js";
import { truncate } from "./text.js";

export const ENGINE_VERSION = "1.0.0";
export const REPORT_SCHEMA = "phishexplain-shield-report/1";
export const LIBRARIES = Object.freeze({ "postal-mime": "4.2.1", tldts: "7.5.5" });

export const CHECKS_PERFORMED = Object.freeze([
  "MIME / RFC 5322 parsing (postal-mime)",
  "Sender identity consistency (From, Reply-To, Return-Path, display name)",
  "Registrable-domain comparison using the Public Suffix List (tldts)",
  "URL structure inspection for text and HTML links (no URL was visited)",
  "Brand look-alike and confusable-character heuristics (limited brand list)",
  "Received-hop parsing and Authentication-Results claim extraction (unverified)",
  "Attachment name, declared type and leading-byte signature metadata",
  "Social-engineering language cues with negation/quotation safeguards"
]);
export const CHECKS_NOT_PERFORMED = Object.freeze([
  "SPF / DKIM / DMARC verification (pasted headers are unverified claims)",
  "Live URL reputation lookup (unless separately requested and configured)",
  "Following redirects or loading any web page",
  "Malware or sandbox scanning of attachments",
  "Inbox integration, quarantine, blocking or deletion",
  "Sender reputation or history"
]);
export const LIMITATIONS = Object.freeze([
  "Absence of indicators does not mean a message is safe; many attacks (especially business email compromise) contain no links or attachments.",
  "The attention index uses fixed, uncalibrated weights. It has not been validated on a representative, permissioned email benchmark.",
  "Language rules are English-only lexical patterns and can miss paraphrases or match legitimate messages.",
  "Brand look-alike detection covers only a short list of frequently impersonated organizations.",
  "Authentication results in pasted headers can be forged and were not verified.",
  "Attachments were not scanned for malware; only names, declared types and leading bytes were inspected."
]);

function newReportId(now) {
  const rand = (globalThis.crypto?.randomUUID?.() || Math.random().toString(16).slice(2) + Date.now().toString(16)).replace(/-/g, "").slice(0, 10).toUpperCase();
  return "PXS-" + now.toISOString().slice(0, 10).replace(/-/g, "") + "-" + rand;
}

/**
 * Analyze an email locally.
 * @param {string|ArrayBuffer|Uint8Array} input
 * @param {{source?: string, fileName?: string, now?: Date, reportId?: string}} opts
 * @returns {Promise<{report: object, context: object}>} report is safe to export; context holds the analyzed text for on-screen highlighting only.
 */
export async function analyzeEmail(input, opts = {}) {
  const now = opts.now instanceof Date ? opts.now : new Date();
  const started = (globalThis.performance?.now?.() ?? Date.now());
  const model = await parseMessage(input, opts);

  const sender = analyzeSender(model);
  const headers = analyzeHeaders(model, sender.summary.domain);

  const htmlOnlyBody = model.input.kind === "body_text" && model.html;
  const bodyText = htmlOnlyBody ? "" : model.text;
  const linkParts = [
    { kind: "text", content: bodyText.slice(0, LIMITS.maxAnalyzedTextChars), location: "body:text" },
    { kind: "html", content: model.html.slice(0, LIMITS.maxAnalyzedTextChars * 2), location: "body:html" },
    { kind: "text", content: model.html_text.slice(0, LIMITS.maxAnalyzedTextChars), location: "body:html (visible text)" }
  ];
  const { links, forms } = collectLinks(linkParts);

  const segments = [];
  if (model.subject) segments.push({ text: model.subject, location: "header:Subject" });
  if (bodyText.trim()) segments.push({ text: bodyText, location: "body:text" });
  else if (model.html_text) segments.push({ text: model.html_text, location: "body:html (visible text)" });
  const language = analyzeLanguage(segments, LIMITS.maxAnalyzedTextChars);
  const attachments = analyzeAttachments(model.attachments);

  const findings = [...sender.findings, ...headers.findings, ...links.flatMap(l => l.findings), ...attachments.findings, ...language.findings];
  for (const f of forms) findings.push(makeFinding("html.form", { evidence: `HTML form${f.action ? " submitting to " + truncate(f.action, 80) : " with no action"}${f.has_password_field ? " containing a password field" : ""}`, source: f.location, url: f.action || null, priority: "high", points: f.has_password_field ? 30 : 24 }));

  const active = rule => findings.some(f => f.rule === rule && f.points > 0);
  const pressure = active("lang.urgency") || active("lang.account-threat");
  const sensitive = ["lang.credential", "lang.otp", "lang.payment"].filter(active);
  if (pressure && sensitive.length) findings.push(makeFinding("combo.pressure-sensitive", { evidence: [active("lang.urgency") && "urgency", active("lang.account-threat") && "account threat"].filter(Boolean).join(" + ") + " together with " + sensitive.map(s => s.split(".")[1]).join(" + ") + " request", source: "body" }));
  const riskyLink = links.find(l => l.findings.some(f => ["high", "medium"].includes(f.priority)));
  if (active("lang.credential") && riskyLink) findings.push(makeFinding("combo.link-credential", { evidence: `Credential wording plus link to ${riskyLink.registrable_domain || riskyLink.host} with structural warnings`, source: "body", url: riskyLink.url, domain: riskyLink.registrable_domain || riskyLink.host }));

  const order = p => PRIORITIES.indexOf(p);
  findings.sort((a, b) => order(a.priority) - order(b.priority) || b.points - a.points || a.rule.localeCompare(b.rule));
  findings.forEach((f, i) => { f.id = "F" + String(i + 1).padStart(2, "0") + "-" + f.rule; });

  const attention = attentionIndex(findings);
  const elapsed = Math.round(((globalThis.performance?.now?.() ?? Date.now()) - started) * 10) / 10;

  const report = {
    schema: REPORT_SCHEMA,
    report_id: opts.reportId || newReportId(now),
    created_at: now.toISOString(),
    engine: { name: "phishexplain-shield-local", version: ENGINE_VERSION, language_ruleset: LANGUAGE_RULESET, libraries: LIBRARIES, runtime: "client-side (browser) — message content was not uploaded", duration_ms: elapsed },
    input: { ...model.input, warnings: [...model.input.warnings] },
    message: {
      subject: model.subject,
      date: model.date,
      message_id: model.message_id,
      to: model.to.slice(0, 20),
      cc: model.cc.slice(0, 20),
      parts: { text: Boolean(model.text), html: Boolean(model.html), attachments: model.attachments.length, headers: model.headers.length }
    },
    sender: sender.summary,
    headers: { received: headers.received, authentication: headers.authentication, alignment: headers.alignment },
    links: links.map(({ findings: lf, ...rest }) => ({ ...rest, finding_ids: lf.map(f => f.id) })),
    attachments: attachments.attachments.map(a => ({ ...a, finding_ids: findings.filter(f => f.category === "attachment" && f.details?.filename === (a.filename || "(unnamed)")).map(f => f.id) })),
    language: { ruleset: language.ruleset, span_count: language.spans.length, spans: language.spans.map(s => ({ category: s.category, rule: s.rule, text: s.text, start: s.start, end: s.end, location: s.location, context_flags: s.context_flags })) },
    findings,
    observed_summary: {
      findings: findings.length,
      weighted_findings: findings.filter(f => f.points > 0).length,
      by_priority: Object.fromEntries(PRIORITIES.map(p => [p, findings.filter(f => f.priority === p).length])),
      by_category: findings.reduce((acc, f) => (acc[f.category] = (acc[f.category] || 0) + 1, acc), {}),
      links: links.length,
      attachments: model.attachments.length
    },
    attention,
    intelligence: { status: "not_requested", note: "No external reputation service was queried for this report.", results: [] },
    ai_analysis: { status: "not_requested", note: "No AI model received this message.", findings: [] },
    recommendations: recommendations(findings, attention),
    checks: { performed: CHECKS_PERFORMED, not_performed: CHECKS_NOT_PERFORMED },
    limitations: LIMITATIONS
  };
  const context = { segments: segments.map(s => ({ location: s.location, text: s.text.slice(0, LIMITS.maxAnalyzedTextChars) })), html_present: Boolean(model.html) };
  return { report, context };
}

/** Structural validation of a report (used by tests, imports, and before export). Throws on failure. */
export function validateReport(r) {
  const fail = m => { throw new Error("Invalid Shield report: " + m); };
  if (!r || typeof r !== "object") fail("not an object");
  if (r.schema !== REPORT_SCHEMA) fail("schema");
  if (typeof r.report_id !== "string" || !/^PXS-\d{8}-[A-Z0-9]{4,}$/.test(r.report_id)) fail("report_id");
  if (Number.isNaN(Date.parse(r.created_at))) fail("created_at");
  if (!Array.isArray(r.findings)) fail("findings");
  const ids = new Set();
  for (const f of r.findings) {
    for (const k of ["id", "rule", "category", "basis", "title", "evidence", "source", "priority", "why", "false_positive_notes", "next_action"]) if (typeof f[k] !== "string" || !f[k]) fail(`finding.${k}`);
    if (!["observed", "heuristic"].includes(f.basis)) fail("finding.basis");
    if (!PRIORITIES.includes(f.priority)) fail("finding.priority");
    if (!Number.isFinite(f.points) || f.points < 0) fail("finding.points");
    if (ids.has(f.id)) fail("duplicate finding id"); ids.add(f.id);
  }
  const a = r.attention;
  if (!a || !Number.isInteger(a.index) || a.index < 0 || a.index > 100 || a.type !== "uncalibrated_heuristic_attention_index") fail("attention");
  if (r.headers?.authentication?.verified !== false) fail("authentication must be unverified for local analysis");
  if (!Array.isArray(r.links) || !Array.isArray(r.attachments) || !Array.isArray(r.recommendations)) fail("collections");
  for (const at of r.attachments) if (at.malware_scanned !== false) fail("attachment malware_scanned must be false");
  if (!["not_requested", "unavailable", "completed", "partial", "error"].includes(r.intelligence?.status)) fail("intelligence.status");
  return true;
}
