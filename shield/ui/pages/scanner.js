import { analyzeEmail, LIMITATIONS } from "../../core/analyze.js";
import { LIMITS } from "../../core/parse.js";
import { $, $$, h, setStatus, chip } from "../dom.js";
import { SAMPLES } from "../samples.js";
import { getCurrent, setCurrent, getSettings, saveToHistory, isSaved } from "../store.js";
import { summaryCard, findingsList, recommendationsEl, linksTable, authTable, senderTable, attachmentsTable, exportReport, printReport } from "../render.js";

let pendingFile = null; // { data: ArrayBuffer|string, name, source }

export function init() {
  const input = $("#email-input"), status = $("#scan-status");
  $("#limitations-list").replaceChildren(...LIMITATIONS.map(t => h("li", { text: t })));

  const updateMeta = () => { $("#input-meta").textContent = input.value.length.toLocaleString() + " characters"; };
  input.addEventListener("input", () => { pendingFile = null; updateMeta(); });

  for (const s of SAMPLES) {
    $("#samples").append(h("button", { class: "btn small", attrs: { type: "button", "data-sample": s.id }, text: s.label, on: { click: () => { selectTab("paste"); input.value = s.text; pendingFile = null; updateMeta(); setStatus(status, `Loaded synthetic example “${s.label}”. Select Analyze email.`); } } }));
  }

  // Tabs (WAI-ARIA tabs pattern with arrow-key navigation)
  const tabs = $$('[role="tab"]');
  function selectTab(which) {
    for (const t of tabs) {
      const on = t.id === "tab-" + which;
      t.setAttribute("aria-selected", String(on)); t.tabIndex = on ? 0 : -1;
      $("#" + t.getAttribute("aria-controls")).hidden = !on;
    }
  }
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => selectTab(t.id.slice(4)));
    t.addEventListener("keydown", e => { if (e.key === "ArrowRight" || e.key === "ArrowLeft") { const n = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length]; selectTab(n.id.slice(4)); n.focus(); } });
  });

  // File import
  const fileInput = $("#file-input"), zone = $("#dropzone");
  const takeFile = async file => {
    if (!file) return;
    if (file.size > LIMITS.maxInputBytes) { setStatus(status, `File is ${(file.size / 1048576).toFixed(1)} MB; the limit is ${LIMITS.maxInputBytes / 1048576} MB.`, "error"); return; }
    const isEml = /\.eml$/i.test(file.name) || file.type === "message/rfc822";
    if (!isEml && !/\.txt$/i.test(file.name) && !file.type.startsWith("text/")) { setStatus(status, "Only .eml and .txt files are supported.", "error"); return; }
    pendingFile = { data: isEml ? await file.arrayBuffer() : await file.text(), name: file.name, source: isEml ? "eml_file" : "txt_file" };
    $("#file-meta").textContent = `Selected ${file.name} (${(file.size / 1024).toFixed(1)} KB). Read locally — not uploaded.`;
    setStatus(status, `File ${file.name} ready. Select Analyze email.`);
  };
  fileInput.addEventListener("change", () => takeFile(fileInput.files?.[0]));
  zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("drag"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag"));
  zone.addEventListener("drop", e => { e.preventDefault(); zone.classList.remove("drag"); takeFile(e.dataTransfer?.files?.[0]); });

  $("#clear").addEventListener("click", () => { input.value = ""; pendingFile = null; fileInput.value = ""; $("#file-meta").textContent = "No file selected. Files are read locally and never uploaded."; updateMeta(); setStatus(status, "Cleared."); input.focus(); });

  $("#analyze").addEventListener("click", async () => {
    const fileMode = $("#tab-file").getAttribute("aria-selected") === "true";
    let data, opts;
    if (fileMode) { if (!pendingFile) { setStatus(status, "Choose an .eml or .txt file first.", "error"); return; } data = pendingFile.data; opts = { source: pendingFile.source, fileName: pendingFile.name }; }
    else { if (!input.value.trim()) { setStatus(status, "Paste an email or choose a synthetic example first.", "error"); input.focus(); return; } data = input.value; opts = { source: "paste" }; }
    const btn = $("#analyze");
    btn.disabled = true; setStatus(status, "Analyzing locally…");
    try {
      const { report, context } = await analyzeEmail(data, opts);
      if (!setCurrent({ report, context })) setStatus(status, "Analysis complete, but this browser blocked session storage, so other Shield pages cannot see it.", "error");
      let saved = false;
      const settings = getSettings();
      if (settings.historyEnabled && settings.autoSave) { try { saveToHistory(report); saved = true; } catch { /* reported in panel */ } }
      renderResult(report);
      setStatus(status, `Analysis complete: ${report.findings.length} finding(s), attention index ${report.attention.index} (${report.attention.label}).${saved ? " Saved to local history." : ""}`, "ok");
      $("#result-heading")?.focus();
    } catch (err) {
      setStatus(status, "Could not analyze: " + (err?.message || "unknown error"), "error");
    } finally { btn.disabled = false; }
  });

  const current = getCurrent();
  if (current?.report) { renderResult(current.report); setStatus(status, "Showing your most recent analysis from this tab."); }
}

function renderResult(report) {
  $("#empty-state").classList.add("hidden");
  const host = $("#result");
  host.classList.remove("hidden");
  const settings = getSettings();
  const saveBtn = h("button", { class: "btn small", attrs: { type: "button" }, text: isSaved(report.report_id) ? "Saved to history ✓" : "Save to history", disabled: isSaved(report.report_id) });
  const saveNote = h("p", { class: "hint", attrs: { role: "status" } });
  saveBtn.addEventListener("click", () => {
    if (!getSettings().historyEnabled) { saveNote.textContent = "Local history is off. Enable it in Settings to save investigations."; return; }
    try { saveToHistory(report); saveBtn.textContent = "Saved to history ✓"; saveBtn.disabled = true; saveNote.textContent = "Saved in this browser only."; } catch (e) { saveNote.textContent = e.message; }
  });
  const high = report.findings.filter(f => f.priority !== "info");
  const info = report.findings.filter(f => f.priority === "info");
  host.replaceChildren(
    h("h3", { class: "sr-only", id: "result-heading", attrs: { tabindex: "-1" }, text: "Results" }),
    summaryCard(report),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("div", {}, h("h2", { text: "What stood out" }), h("p", { class: "card-sub", text: "Select a finding to see the evidence, why it matters, and how it could be legitimate." })), chip(report.findings.length + " total")),
      findingsList(high, "No weighted indicators matched. This does not mean the message is safe."),
      info.length ? h("details", { class: "mt-14" }, h("summary", { class: "small muted", text: `${info.length} informational or context-safeguarded item(s)` }), h("div", { class: "mt-10" }, findingsList(info))) : null),
    h("div", { class: "card" }, h("h2", { text: "Safer next steps" }), recommendationsEl(report.recommendations)),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", { text: "Link destinations" }), h("a", { class: "btn small", href: "/security/links/", text: "Open in URL inspector" })), linksTable(report)),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", { text: "Sender & authentication claims" }), h("a", { class: "btn small", href: "/security/headers/", text: "Header analyzer" })), senderTable(report.sender), h("div", { class: "mt-14" }, authTable(report.headers.authentication))),
    h("div", { class: "card" }, h("h2", { text: "Attachments" }), attachmentsTable(report)),
    h("div", { class: "card no-print" }, h("h2", { text: "Export & continue" }),
      h("div", { class: "row" },
        h("button", { class: "btn", attrs: { type: "button" }, text: "JSON", on: { click: () => exportReport(report, "json") } }),
        h("button", { class: "btn", attrs: { type: "button" }, text: "CSV", on: { click: () => exportReport(report, "csv") } }),
        h("button", { class: "btn", attrs: { type: "button" }, text: "HTML report", on: { click: () => exportReport(report, "html") } }),
        h("button", { class: "btn", attrs: { type: "button" }, text: "Print / PDF", on: { click: printReport } }),
        saveBtn),
      settings.historyEnabled ? null : h("p", { class: "hint" }, "Local history is off. ", h("a", { href: "/security/settings/", text: "Enable it in Settings" }), " to track this investigation."),
      saveNote,
      h("div", { class: "row mt-12" }, h("a", { class: "btn small", href: "/security/analysis/", text: "Explainable analysis →" }), h("a", { class: "btn small", href: "/security/reports/", text: "Report view →" })))
  );
}
