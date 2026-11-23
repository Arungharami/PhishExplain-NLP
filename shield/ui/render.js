// Shared rendering components for Shield pages. All email-derived values are inserted as text.
import { h, svg, chip, fmtDate, fmtBytes, download } from "./dom.js";
import { toJSON, toCSV, toHTML } from "../core/report.js";

const PRI_LABEL = { high: "High", medium: "Medium", low: "Low", info: "Info" };
const SOURCE_LABEL = s => String(s).replace(/^header:/, "Header: ").replace(/^body:/, "Body: ").replace(/^attachment:/, "Attachment: ");

export function gauge(index, band) {
  const r = 52, c = 2 * Math.PI * r;
  const bar = svg("circle", { class: "bar", cx: 64, cy: 64, r, "stroke-dasharray": c.toFixed(2), "stroke-dashoffset": (c * (1 - index / 100)).toFixed(2) });
  return svg("svg", { class: "gauge band-" + band, viewBox: "0 0 128 128", role: "img", "aria-label": `Heuristic attention index ${index} out of 100` },
    svg("circle", { class: "track", cx: 64, cy: 64, r }), bar,
    svg("text", { x: 64, y: 68 }, String(index)), svg("text", { x: 64, y: 88, class: "sub" }, "of 100"));
}

export function summaryCard(report, { compact = false } = {}) {
  const a = report.attention, s = report.observed_summary;
  const row = (k, v) => v ? [h("dt", { text: k }), h("dd", { class: "mono", text: v })] : null;
  const from = report.sender.address ? (report.sender.display_name ? `${report.sender.display_name} <${report.sender.address}>` : report.sender.address) : null;
  const metaRows = [row("Subject", report.message.subject), row("From", from), row("Input", `${report.input.kind.replace("_", " ")} · ${report.input.source}${report.input.file_name ? " · " + report.input.file_name : ""}`), row("Report ID", report.report_id)].filter(Boolean);
  return h("div", { class: "card" },
    h("div", { class: "summary" }, gauge(a.index, a.band),
      h("div", {},
        h("span", { class: "kicker", text: "Heuristic attention index" }),
        h("h2", { text: a.label }),
        h("p", { text: a.summary }),
        h("p", { class: "tiny muted", text: "Uncalibrated review priority — not a probability of phishing. A low value never means the message is safe." }))),
    h("div", { class: "stats" },
      stat(s.findings, "Findings"), stat(s.by_priority.high, "High priority"), stat(s.links, "Links (not visited)"), stat(s.attachments, "Attachments")),
    compact ? null : h("dl", { class: "kv mt-14" }, metaRows),
    report.input.warnings?.length ? h("div", { class: "alert warn mt-12 small" }, h("strong", { text: "Parsing notes: " }), report.input.warnings.join(" ")) : null);
}
const stat = (n, label) => h("div", { class: "stat" }, h("strong", { text: String(n ?? 0) }), h("span", { text: label }));

export function findingEl(f, { open = false } = {}) {
  const d = h("details", { class: "finding p-" + f.priority, open });
  d.dataset.findingId = f.id;
  const flags = f.context_flags?.length ? f.context_flags.map(x => x.replace("_", " ")).join(", ") : null;
  d.append(
    h("summary", {},
      h("span", { class: "pri " + f.priority, text: PRI_LABEL[f.priority] }),
      h("span", {}, h("span", { class: "ftitle", text: f.title }), h("span", { class: "fev", text: f.evidence })),
      h("span", { class: "fmeta", text: (f.basis === "observed" ? "Observed" : "Heuristic") + " · " + f.category })),
    h("div", { class: "fbody" }, h("dl", {},
      dt("Evidence"), h("dd", { text: f.evidence }),
      f.excerpt ? [dt("Context"), h("dd", { class: "mono", text: f.excerpt })] : null,
      dt("Source"), h("dd", { text: SOURCE_LABEL(f.source) }),
      f.domain ? [dt("Domain"), h("dd", { class: "mono", text: f.domain })] : null,
      f.url ? [dt("URL (not visited)"), h("dd", { class: "mono", text: f.url })] : null,
      f.details?.legitimate_domains?.length ? [dt("Known domains"), h("dd", { class: "mono", text: f.details.legitimate_domains.join(", ") })] : null,
      dt("Why it matters"), h("dd", { text: f.why }),
      dt("Could be legitimate if"), h("dd", { text: f.false_positive_notes }),
      flags ? [dt("Context safeguard"), h("dd", { text: `Matches look ${flags}; they are shown but not weighted.` })] : null,
      dt("Recommended action"), h("dd", { text: f.next_action }),
      dt("Index weight"), h("dd", { text: f.points ? `+${f.points} (before category caps)` : "Not weighted" }))));
  return d;
}
const dt = t => h("dt", { text: t });

export function findingsList(findings, emptyText = "No indicators matched. This does not mean the message is safe.") {
  if (!findings.length) return h("p", { class: "muted", text: emptyText });
  return h("div", { class: "findings" }, findings.map(f => findingEl(f)));
}

export function recommendationsEl(recs) {
  return h("ol", { class: "stack" }, recs.map(r => h("li", {}, h("strong", { text: r.title + ". " }), r.detail)));
}

export function linksTable(report) {
  if (!report.links.length) return h("p", { class: "muted", text: "No web links were found in this message." });
  const byId = new Map(report.findings.map(f => [f.id, f]));
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Destination (not visited)", "Registered domain", "Seen as", "Indicators"].map(t => h("th", { attrs: { scope: "col" }, text: t })))),
    h("tbody", {}, report.links.map(l => h("tr", {},
      h("td", {}, h("span", { class: "mono", text: l.url })),
      h("td", {}, h("span", { class: "mono", text: l.registrable_domain || l.host || "—" }), l.is_idn ? h("div", { class: "tiny muted", text: "Displays as " + l.host_unicode }) : null),
      h("td", { class: "small", text: [...new Set(l.sources.map(s => s.display_text ? `“${s.display_text}”` : SOURCE_LABEL(s.location)))].join("; ") }),
      h("td", {}, l.finding_ids.length ? l.finding_ids.map(id => byId.get(id)).filter(Boolean).map(f => h("div", {}, chip(f.title, f.priority === "high" ? "danger" : f.priority === "medium" ? "warn" : "muted"))) : chip("No structural indicators", "ok")))))));
}

export function authTable(auth) {
  const row = c => h("tr", {}, h("th", { attrs: { scope: "row" }, text: c.method.toUpperCase() }), h("td", { text: c.result || "—" }), h("td", { class: "mono", text: c.domain || "—" }), h("td", {}, c.status === "unverified_claim" ? chip("Unverified claim" + (c.claimed_by ? " · " + c.claimed_by : ""), "warn") : chip("Not present", "muted")));
  return h("div", {},
    h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Check", "Claimed result", "Domain", "Trust"].map(t => h("th", { attrs: { scope: "col" }, text: t })))), h("tbody", {}, row(auth.spf), row(auth.dkim), row(auth.dmarc)))),
    h("p", { class: "tiny muted mt-10", text: auth.explanation }));
}

export function senderTable(sender) {
  const rows = [
    ["Display name", sender.display_name], ["From address", sender.address], ["Registered domain", sender.registrable_domain + (sender.domain_unicode && sender.domain_unicode !== sender.domain ? ` (displays as ${sender.domain_unicode})` : "")],
    ["Reply-To", (sender.reply_to || []).map(r => `${r.address} (${r.registrable_domain || "?"})`).join(", ")], ["Return-Path", sender.return_path ? `${sender.return_path} (${sender.return_path_registrable || "?"})` : null], ["Sender header", sender.sender_header],
    ["Free webmail domain", sender.address ? (sender.is_free_mail ? "Yes" : "No") : null], ["Known brand domain", sender.brand_domain]
  ].filter(([, v]) => v && v !== "null");
  if (!rows.length) return h("p", { class: "muted", text: "No sender headers were supplied. Paste the full raw message to compare sender fields." });
  return h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, rows.map(([k, v]) => h("tr", {}, h("th", { attrs: { scope: "row" }, text: k }), h("td", { class: "mono", text: v }))))));
}

export function hopsTimeline(hops) {
  if (!hops.length) return h("p", { class: "muted", text: "No Received headers were supplied." });
  return h("ol", { class: "timeline" }, hops.map(hp => h("li", {},
    h("span", { class: "num", text: String(hp.hop), attrs: { "aria-hidden": "true" } }),
    h("div", { class: "hop-main", text: `${hp.from_host || "unknown"} → ${hp.by_host || "unknown"}` }),
    h("div", { class: "hop-meta" }, [hp.from_ip ? `IP ${hp.from_ip}${hp.from_ip_private ? " (private range)" : ""}` : null, hp.helo_ip ? `HELO claimed ${hp.helo_ip}` : null, hp.protocol ? `via ${hp.protocol}` : null, hp.timestamp ? fmtDate(hp.timestamp) : (hp.date_text ? "date unparsed" : "no date"), hp.delay_seconds !== null && hp.delay_seconds !== undefined ? `Δ ${hp.delay_seconds}s` : null].filter(Boolean).join(" · ")))));
}

export function attachmentsTable(report) {
  if (!report.attachments.length) return h("p", { class: "muted", text: "No attachments." });
  return h("div", {}, h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["File name", "Declared type", "Size", "Content signature", "Indicators"].map(t => h("th", { attrs: { scope: "col" }, text: t })))),
    h("tbody", {}, report.attachments.map(a => h("tr", {}, h("td", { class: "mono", text: a.filename || "(unnamed)" }), h("td", { class: "small", text: a.mime_type || "—" }), h("td", { class: "small", text: fmtBytes(a.size_bytes) }), h("td", { class: "small", text: a.detected_signature || "unrecognized" }), h("td", {}, a.flags.length ? a.flags.map(f => h("div", {}, chip(f.replace("attach.", "").replace("-", " "), "warn"))) : chip("None", "ok"))))))),
    h("p", { class: "tiny muted mt-10", text: "Attachments were not scanned for malware. Only names, declared types, sizes and leading bytes were inspected." }));
}

const INTEL_KIND = { listed: "danger", flagged: "danger", not_listed: "muted", no_record: "muted", unavailable: "warn", not_configured: "muted" };
const INTEL_LABEL = { listed: "Listed by provider", flagged: "Flagged by vendors", not_listed: "No listing found", no_record: "No record", unavailable: "Lookup unavailable", not_configured: "Not configured" };
export function intelTable(results) {
  if (!results?.length) return h("p", { class: "muted", text: "Reputation lookup not run for this analysis. Use the URL Inspection Center to request one (optional, consent required)." });
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Provider", "Queried", "Result", "Details", "Checked"].map(t => h("th", { attrs: { scope: "col" }, text: t })))),
    h("tbody", {}, results.map(r => h("tr", {},
      h("td", { class: "small", text: r.provider.replace(/_/g, " ") }), h("td", { class: "mono small", text: r.query }), h("td", {}, chip(INTEL_LABEL[r.status] || r.status, INTEL_KIND[r.status] || "")),
      h("td", { class: "small" }, r.summary, r.reference ? [" ", h("a", { href: r.reference, text: "Provider page", attrs: { target: "_blank", rel: "noopener noreferrer" } })] : null),
      h("td", { class: "small", text: fmtDate(r.checked_at) + (r.cache_age_seconds ? ` (cached ${r.cache_age_seconds}s)` : "") }))))));
}

/** Render text with highlighted spans (spans must have start/end/category). */
export function highlighted(text, spans) {
  const host = document.createDocumentFragment();
  const sorted = [...spans].filter(s => Number.isInteger(s.start) && s.end > s.start && s.end <= text.length).sort((a, b) => a.start - b.start || b.end - a.end);
  let pos = 0;
  for (const s of sorted) {
    if (s.start < pos) continue;
    host.append(document.createTextNode(text.slice(pos, s.start)));
    const cls = s.ai ? "m-ai" : s.context_flags?.length ? "m-flagged" : "m-" + s.category;
    host.append(h("mark", { class: cls, text: text.slice(s.start, s.end), attrs: { title: (s.ai ? "AI: " : "") + s.category.replace(/_/g, " ") + (s.context_flags?.length ? " (" + s.context_flags.join(", ") + ")" : "") } }));
    pos = s.end;
  }
  host.append(document.createTextNode(text.slice(pos)));
  return host;
}

export function exportReport(report, kind) {
  const base = "phishexplain-" + report.report_id;
  if (kind === "json") download(toJSON(report), base + ".json", "application/json");
  else if (kind === "csv") download(toCSV(report), base + "-findings.csv", "text/csv;charset=utf-8");
  else if (kind === "html") download(toHTML(report), base + ".html", "text/html;charset=utf-8");
}

/** Expand all findings for printing and restore afterwards. */
export function printReport() {
  const closed = [...document.querySelectorAll("details.finding:not([open])")];
  closed.forEach(d => { d.open = true; });
  const restore = () => { closed.forEach(d => { d.open = false; }); window.removeEventListener("afterprint", restore); };
  window.addEventListener("afterprint", restore);
  window.print();
}
