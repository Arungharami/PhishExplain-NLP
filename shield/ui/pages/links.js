import { inspectUrl } from "../../core/urls.js";
import { $, h, setStatus, chip } from "../dom.js";
import { getCurrent, setCurrent, getKey, setKey, isSaved, saveToHistory } from "../store.js";
import { findingsList, intelTable } from "../render.js";
import { reputationStatus, runReputation } from "../api.js";

const MAX_LINES = 50;
let inspected = [];

export function init() {
  const status = $("#url-status");
  $("#inspect").addEventListener("click", () => {
    const lines = $("#url-input").value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    if (!lines.length) { setStatus(status, "Enter at least one URL.", "error"); return; }
    if (lines.length > MAX_LINES) setStatus(status, `Only the first ${MAX_LINES} lines are inspected.`);
    inspect(lines.slice(0, MAX_LINES), "manual input");
  });
  $("#use-current").addEventListener("click", () => {
    const cur = getCurrent();
    if (!cur?.report?.links?.length) { setStatus(status, cur?.report ? "The current scan contains no web links." : "No current scan in this tab. Run the scanner first.", "error"); return; }
    $("#url-input").value = cur.report.links.map(l => l.url).join("\n");
    inspect(cur.report.links.map(l => l.url), "current scan");
  });
  if (getCurrent()?.report?.links?.length) setStatus(status, `Your current scan has ${getCurrent().report.links.length} link(s). Select “Load links from current scan”.`);
  setupReputation();
}

function inspect(lines, origin) {
  const status = $("#url-status");
  inspected = [];
  const cards = [];
  for (const raw of lines) {
    let rec = null;
    try { rec = inspectUrl({ raw, location: origin, offset: 0, display_text: null }); } catch { rec = null; }
    if (!rec) { cards.push(h("div", { class: "card" }, h("p", {}, h("span", { class: "mono", text: raw }), " — ", h("span", { class: "muted", text: "not an http(s) web address; skipped." })))); continue; }
    inspected.push(rec);
    const rows = [["Scheme", rec.scheme], ["Hostname", rec.host], ["Displays as", rec.host_unicode !== rec.host ? rec.host_unicode : null], ["Registered domain", rec.registrable_domain || (rec.is_ip ? "IP address (no domain)" : "—")], ["Public suffix", rec.public_suffix], ["Subdomain", rec.subdomain], ["Port", rec.port], ["Path", rec.path]].filter(([, v]) => v);
    cards.push(h("article", { class: "card" },
      h("div", { class: "card-head" }, h("div", {}, h("h3", { class: "mono", text: rec.url }), h("p", { class: "card-sub", text: "Parsed as text — not visited." })), rec.findings.length ? chip(rec.findings.length + " indicator(s)", rec.findings.some(f => f.priority === "high") ? "danger" : "warn") : chip("No structural indicators", "ok")),
      h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, rows.map(([k, v]) => h("tr", {}, h("th", { attrs: { scope: "row" }, text: k }), h("td", { class: "mono", text: v })))))),
      h("div", { class: "mt-14" }, findingsList(rec.findings, "No structural indicators. This does not mean the destination is safe."))));
  }
  $("#url-results").replaceChildren(...cards);
  setStatus(status, `Inspected ${inspected.length} URL(s) from ${origin}. No URL was opened.`, "ok");
  updateRepButton();
}

let repConfig = null;
async function setupReputation() {
  const cfgChip = $("#rep-config");
  const { ok, data } = await reputationStatus();
  repConfig = ok ? data : null;
  if (!ok) { cfgChip.textContent = "Reputation lookup unavailable"; cfgChip.className = "chip muted"; setStatus($("#rep-status"), data?.error || "The reputation service could not be reached."); return; }
  const names = Object.entries(data.providers).filter(([, v]) => v).map(([k]) => k.replace(/_/g, " "));
  if (!data.available) { cfgChip.textContent = "Reputation lookup unavailable"; cfgChip.className = "chip muted"; setStatus($("#rep-status"), names.length ? "Providers are configured but access control is not, so lookups are disabled." : "No reputation provider is configured on this deployment. No reputation score is substituted."); return; }
  cfgChip.textContent = "Available: " + names.join(", "); cfgChip.className = "chip ok";
  $("#rep-controls").classList.remove("hidden");
  if (data.access === "access_key_required") { $("#rep-key-field").classList.remove("hidden"); $("#rep-key").value = getKey(); }
  $("#rep-consent").addEventListener("change", updateRepButton);
  $("#rep-run").addEventListener("click", runLookup);
}
function updateRepButton() { const b = $("#rep-run"); if (b) b.disabled = !($("#rep-consent")?.checked && inspected.length); }

async function runLookup() {
  const status = $("#rep-status");
  const urls = [...new Set(inspected.map(r => r.normalized))].slice(0, repConfig?.max_urls_per_request || 10);
  if (!urls.length) { setStatus(status, "Inspect at least one URL first.", "error"); return; }
  const key = $("#rep-key")?.value || "";
  if (repConfig.access === "access_key_required" && !key) { setStatus(status, "Enter the Shield access key.", "error"); return; }
  if (key) setKey(key);
  $("#rep-run").disabled = true; setStatus(status, `Querying providers for ${urls.length} URL(s)…`);
  const { ok, status: code, data } = await runReputation(urls, key);
  $("#rep-run").disabled = false;
  if (!ok) { setStatus(status, `Reputation lookup unavailable: ${data?.error || "HTTP " + code}`, "error"); return; }
  const results = data.checks.flatMap(c => c.ok ? c.results : []);
  const skipped = data.checks.filter(c => !c.ok);
  $("#rep-results").replaceChildren(intelTable(results), ...skipped.map(s => h("p", { class: "small muted" }, h("span", { class: "mono", text: s.input }), " — " + s.reason)));
  setStatus(status, `Lookup ${data.status}: ${results.filter(r => r.status === "listed" || r.status === "flagged").length} provider listing(s) found. ${data.note}`, "ok");
  // Attach to the current analysis when these URLs came from it.
  const cur = getCurrent();
  if (cur?.report) {
    const own = new Set(cur.report.links.map(l => l.normalized));
    const relevant = results.filter(r => own.has(r.query));
    if (relevant.length) {
      cur.report.intelligence = { status: data.status, note: "Results returned by external providers via the Shield server. 'No listing found' is not a safety verdict.", requested_at: new Date().toISOString(), results: relevant };
      setCurrent(cur);
      if (isSaved(cur.report.report_id)) { try { saveToHistory(cur.report); } catch { /* ignore */ } }
    }
  }
}
