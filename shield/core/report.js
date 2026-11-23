// Report exports. All generated locally; nothing is transmitted.
// Every value from the email is escaped. Reports never contain API keys or access tokens.

export const escapeHtml = s => String(s ?? "").replace(/[&<>"'`]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" })[c]);

const SECRET_KEYS = /^(x-shield-key|x-research-key|authorization|api[_-]?key|access[_-]?key|token|secret)$/i;
/** Deep copy with any secret-like keys removed (defense in depth; reports should never hold them). */
export function scrubSecrets(value) {
  if (Array.isArray(value)) return value.map(scrubSecrets);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).filter(([k]) => !SECRET_KEYS.test(k)).map(([k, v]) => [k, scrubSecrets(v)]));
  return value;
}

export function toJSON(report) { return JSON.stringify(scrubSecrets(report), null, 2) + "\n"; }

/** CSV cell: quote, double quotes, and neutralize spreadsheet formula injection. */
export function csvCell(v) {
  let s = v === null || v === undefined ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}
export function toCSV(report) {
  const cols = ["report_id", "finding_id", "priority", "category", "basis", "title", "evidence", "source", "domain", "url", "points", "context_flags", "why", "false_positive_notes", "next_action"];
  const rows = [cols.map(csvCell).join(",")];
  for (const f of report.findings) rows.push([report.report_id, f.id, f.priority, f.category, f.basis, f.title, f.evidence, f.source, f.domain, f.url, f.points, (f.context_flags || []).join(" "), f.why, f.false_positive_notes, f.next_action].map(csvCell).join(","));
  for (const r of report.intelligence?.results || []) rows.push([report.report_id, "intel:" + r.provider, r.status === "listed" ? "high" : "info", "intelligence", "verified_external", r.provider + " result", r.summary, "provider:" + r.provider, null, r.query, null, "", "Result returned by external provider at " + r.checked_at, "", ""].map(csvCell).join(","));
  return rows.join("\r\n") + "\r\n";
}

const PRIORITY_LABEL = { high: "High", medium: "Medium", low: "Low", info: "Info" };

/** Standalone printable HTML report (no scripts, no external resources). */
export function toHTML(report) {
  const e = escapeHtml;
  const r = report;
  const intel = r.intelligence || { status: "not_requested", results: [] };
  const ai = r.ai_analysis || { status: "not_requested", findings: [] };
  const auth = r.headers?.authentication || {};
  const authRow = c => `<tr><th>${e(c.method?.toUpperCase())}</th><td>${c.result ? e(c.result) : "—"}</td><td>${e(c.domain || "")}</td><td>${c.status === "unverified_claim" ? "Unverified claim" + (c.claimed_by ? " by " + e(c.claimed_by) : "") : "Not present"}</td></tr>`;
  const findingRows = r.findings.map(f => `<article class="f p-${e(f.priority)}"><header><span class="pri">${e(PRIORITY_LABEL[f.priority])}</span><h3>${e(f.title)}</h3><span class="basis">${f.basis === "observed" ? "Observed" : "Heuristic"} · ${e(f.category)}</span></header>
<dl><dt>Evidence</dt><dd>${e(f.evidence)}</dd>${f.excerpt ? `<dt>Context</dt><dd class="mono">${e(f.excerpt)}</dd>` : ""}<dt>Source</dt><dd class="mono">${e(f.source)}</dd>${f.domain ? `<dt>Domain</dt><dd class="mono">${e(f.domain)}</dd>` : ""}${f.url ? `<dt>URL (not visited)</dt><dd class="mono">${e(f.url)}</dd>` : ""}<dt>Why it matters</dt><dd>${e(f.why)}</dd><dt>Could be legitimate if</dt><dd>${e(f.false_positive_notes)}</dd><dt>Recommended action</dt><dd>${e(f.next_action)}</dd>${f.context_flags?.length ? `<dt>Context safeguards</dt><dd>${e(f.context_flags.join(", "))} — not weighted</dd>` : ""}</dl></article>`).join("\n");
  const links = r.links.map(l => `<tr><td class="mono">${e(l.url)}</td><td class="mono">${e(l.registrable_domain || l.host || "")}</td><td>${e((l.sources || []).map(s => s.display_text ? `"${s.display_text}"` : s.location).join("; "))}</td><td>${l.finding_ids.length}</td></tr>`).join("");
  const atts = r.attachments.map(a => `<tr><td class="mono">${e(a.filename || "(unnamed)")}</td><td>${e(a.mime_type || "")}</td><td>${e(a.size_bytes)}</td><td>${e(a.detected_signature || "unknown")}</td><td>Not scanned</td></tr>`).join("");
  const intelRows = (intel.results || []).map(x => `<tr><td>${e(x.provider)}</td><td class="mono">${e(x.query)}</td><td>${e(x.status)}</td><td>${e(x.summary)}</td><td>${e(x.checked_at)}</td></tr>`).join("");
  const aiRows = (ai.findings || []).map(x => `<li><strong>${e(x.category)}</strong>: “${e(x.quote)}” — ${e(x.explanation)}</li>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'"><title>Shield report ${e(r.report_id)}</title>
<style>
body{font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#0f172a;max-width:960px;margin:0 auto;padding:32px 24px;background:#fff}
h1{font-size:24px;margin:0}h2{font-size:17px;margin:28px 0 10px;border-bottom:1px solid #cbd5e1;padding-bottom:6px}h3{font-size:15px;margin:0;flex:1}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:6px 18px;margin:16px 0;color:#334155}.meta b{color:#0f172a}
.score{border:1px solid #cbd5e1;border-radius:10px;padding:14px 16px;background:#f8fafc}.score strong{font-size:28px}
.note{font-size:12.5px;color:#475569}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all;font-size:12.5px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #e2e8f0;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f1f5f9}
.f{border:1px solid #e2e8f0;border-left:4px solid #94a3b8;border-radius:6px;padding:10px 14px;margin:10px 0;break-inside:avoid}.f header{display:flex;gap:10px;align-items:baseline}
.p-high{border-left-color:#dc2626}.p-medium{border-left-color:#d97706}.p-low{border-left-color:#0891b2}.pri{font-weight:700;font-size:12px;text-transform:uppercase}.basis{font-size:12px;color:#64748b}
dl{display:grid;grid-template-columns:170px 1fr;gap:4px 12px;margin:8px 0 0}dt{color:#475569;font-weight:600}dd{margin:0}
ul{padding-left:20px}.banner{background:#fef3c7;border:1px solid #f59e0b;padding:10px 14px;border-radius:8px;margin:14px 0}
@media print{body{padding:0}.f{page-break-inside:avoid}}
</style></head><body>
<h1>PhishExplain Shield — Email Inspection Report</h1>
<div class="meta"><span><b>Report ID</b> ${e(r.report_id)}</span><span><b>Created</b> ${e(r.created_at)}</span><span><b>Engine</b> ${e(r.engine.name)} v${e(r.engine.version)} (${e(r.engine.language_ruleset)})</span><span><b>Input</b> ${e(r.input.kind)} via ${e(r.input.source)}${r.input.file_name ? " · " + e(r.input.file_name) : ""}</span><span><b>Subject</b> ${e(r.message.subject || "—")}</span><span><b>From</b> ${e(r.sender.display_name ? r.sender.display_name + " " : "")}${e(r.sender.address ? "<" + r.sender.address + ">" : "—")}</span></div>
<div class="banner">This report lists observed indicators and heuristic interpretations. It is not a verdict that the message is or is not malicious.</div>
<div class="score"><strong>${e(r.attention.index)}</strong> / 100 · ${e(r.attention.label)}<p class="note">${e(r.attention.disclaimer)}</p></div>
<h2>Findings (${r.findings.length})</h2>${findingRows || "<p>No indicators matched. This does not mean the message is safe.</p>"}
<h2>Links (${r.links.length}) — none were visited</h2>${links ? `<table><tr><th>URL</th><th>Registered domain</th><th>Seen as</th><th>Findings</th></tr>${links}</table>` : "<p>No web links found.</p>"}
<h2>Sender &amp; authentication claims</h2><table><tr><th>Check</th><th>Claimed result</th><th>Domain</th><th>Trust</th></tr>${authRow(auth.spf || { method: "spf" })}${authRow(auth.dkim || { method: "dkim" })}${authRow(auth.dmarc || { method: "dmarc" })}</table><p class="note">${e(auth.explanation || "")}</p>
<p>Reply-To: ${e((r.sender.reply_to || []).map(x => x.address).join(", ") || "—")} · Return-Path: ${e(r.sender.return_path || "—")} · Received hops: ${e(r.headers?.received?.length ?? 0)}</p>
<h2>Attachments (${r.attachments.length})</h2>${atts ? `<table><tr><th>Name</th><th>Declared type</th><th>Bytes</th><th>Leading-byte signature</th><th>Malware scan</th></tr>${atts}</table>` : "<p>No attachments.</p>"}
<h2>External threat intelligence</h2>${intelRows ? `<table><tr><th>Provider</th><th>Queried</th><th>Status</th><th>Result</th><th>Checked</th></tr>${intelRows}</table>` : `<p>${e(intel.note || "Not requested.")}</p>`}
<h2>AI-assisted analysis</h2>${aiRows ? `<p class="note">Model: ${e(ai.model || "")} · Every quote below was verified to appear in the original message.</p><ul>${aiRows}</ul>` : `<p>${e(ai.note || "Not requested.")}</p>`}
<h2>Safer next steps</h2><ul>${r.recommendations.map(x => `<li><strong>${e(x.title)}.</strong> ${e(x.detail)}</li>`).join("")}</ul>
<h2>Checks</h2><p><b>Performed:</b></p><ul>${r.checks.performed.map(x => `<li>${e(x)}</li>`).join("")}</ul><p><b>Not performed:</b></p><ul>${r.checks.not_performed.map(x => `<li>${e(x)}</li>`).join("")}</ul>
<h2>Limitations</h2><ul>${r.limitations.map(x => `<li>${e(x)}</li>`).join("")}</ul>
${r.input.warnings?.length ? `<h2>Parsing notes</h2><ul>${r.input.warnings.map(x => `<li>${e(x)}</li>`).join("")}</ul>` : ""}
<p class="note">Generated locally by PhishExplain Shield (beta). https://phishexplain-nlp.vercel.app</p>
</body></html>`;
}
