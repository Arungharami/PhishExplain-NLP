import { $, h, setStatus, chip, download, fmtDate } from "../dom.js";
import { getSettings, listHistory, updateHistory, removeFromHistory, addNote, setCurrent, STATUSES } from "../store.js";
import { scrubSecrets } from "../../core/report.js";

let notesFor = null;

export function init() {
  if (!getSettings().historyEnabled) { $("#history-disabled").classList.remove("hidden"); return; }
  $("#dashboard").classList.remove("hidden");
  const filter = $("#status-filter");
  filter.replaceChildren(h("option", { value: "all", text: "All statuses" }), h("option", { value: "open", text: "Open (not resolved)" }), ...STATUSES.map(s => h("option", { value: s.id, text: s.label })));
  filter.addEventListener("change", render);
  $("#export-history").addEventListener("click", () => download(JSON.stringify(scrubSecrets({ exported_at: new Date().toISOString(), source: "PhishExplain Shield local history", items: listHistory() }), null, 2), "phishexplain-history.json", "application/json"));
  $("#notes-close").addEventListener("click", () => { $("#notes-card").classList.add("hidden"); notesFor = null; });
  $("#note-add").addEventListener("click", () => {
    const t = $("#note-input").value.trim();
    if (!notesFor || !t) return;
    addNote(notesFor, t); $("#note-input").value = ""; openNotes(notesFor); render();
  });
  render();
}

function render() {
  const items = listHistory();
  const f = $("#status-filter").value;
  const shown = items.filter(x => f === "all" || (f === "open" ? x.status !== "resolved" : x.status === f)).sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at));
  const listed = items.filter(x => (x.report.intelligence?.results || []).some(r => r.status === "listed" || r.status === "flagged")).length;
  $("#dash-stats").replaceChildren(
    stat(items.length, "Saved analyses"),
    stat(items.filter(x => ["new", "under_review", "needs_verification"].includes(x.status)).length, "Awaiting review"),
    stat(items.filter(x => x.status === "resolved").length, "Resolved"),
    stat(listed, "With provider listings"));
  $("#history-empty").textContent = items.length ? (shown.length ? "" : "No investigations match this filter.") : "No saved analyses yet. Run a scan and choose “Save to history”.";
  $("#history-rows").replaceChildren(...shown.map(row));
}
const stat = (n, label) => h("div", { class: "stat" }, h("strong", { text: String(n) }), h("span", { text: label }));

function row(item) {
  const r = item.report;
  const sel = h("select", { class: "select w-auto", attrs: { "aria-label": "Workflow status for " + (r.message.subject || r.report_id) } }, STATUSES.map(s => h("option", { value: s.id, text: s.label, selected: s.id === item.status })));
  sel.addEventListener("change", () => { updateHistory(r.report_id, { status: sel.value }); setStatus($("#dash-status"), "Status updated to " + sel.selectedOptions[0].text + ".", "ok"); render(); });
  const high = r.findings.filter(x => x.priority === "high").length;
  return h("tr", {},
    h("td", { class: "small", text: fmtDate(item.saved_at) }),
    h("td", {}, h("div", { text: r.message.subject || "(no subject)" }), h("div", { class: "tiny muted mono", text: r.sender.address || "sender not supplied" })),
    h("td", {}, chip(String(r.attention.index), r.attention.band === "high" ? "danger" : r.attention.band === "elevated" ? "warn" : "muted")),
    h("td", { class: "small", text: `${r.findings.length} (${high} high)` + (item.notes.length ? ` · ${item.notes.length} note(s)` : "") }),
    h("td", {}, sel),
    h("td", {}, h("div", { class: "row" },
      h("button", { class: "btn small", attrs: { type: "button" }, text: "Open", on: { click: () => { setCurrent({ report: r, context: null }); location.href = "/security/reports/"; } } }),
      h("button", { class: "btn small", attrs: { type: "button" }, text: "Notes", on: { click: () => openNotes(r.report_id) } }),
      h("button", { class: "btn small danger", attrs: { type: "button" }, text: "Delete", on: { click: () => { if (confirm("Delete this saved analysis from this browser?")) { removeFromHistory(r.report_id); render(); setStatus($("#dash-status"), "Deleted.", "ok"); } } } }))));
}

function openNotes(id) {
  notesFor = id;
  const item = listHistory().find(x => x.report.report_id === id);
  if (!item) return;
  $("#notes-card").classList.remove("hidden");
  $("#notes-title").textContent = "Analyst notes — " + (item.report.message.subject || id);
  $("#notes-list").replaceChildren(...(item.notes.length ? item.notes.map(n => h("li", {}, h("span", { class: "muted", text: fmtDate(n.at) + " — " }), n.text)) : [h("li", { class: "muted", text: "No notes yet." })]));
  $("#note-input").focus();
}
