import { validateReport } from "../../core/analyze.js";
import { $, h, setStatus } from "../dom.js";
import { getCurrent, setCurrent } from "../store.js";
import { summaryCard, findingEl, recommendationsEl, linksTable, authTable, senderTable, attachmentsTable, intelTable, exportReport, printReport, hopsTimeline } from "../render.js";

export function init() {
  const cur = getCurrent();
  if (cur?.report) show(cur.report); else $("#no-report").classList.remove("hidden");
  $("#import-report").addEventListener("change", async e => {
    const file = e.target.files?.[0];
    const status = $("#rp-status");
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) { setStatus(status, "Report file is too large.", "error"); return; }
    try {
      const report = JSON.parse(await file.text());
      validateReport(report);
      setCurrent({ report, context: null });
      $("#no-report").classList.add("hidden");
      show(report);
      setStatus(status, `Loaded report ${report.report_id}. It was validated locally.`, "ok");
    } catch (err) { setStatus(status, "Report rejected: " + err.message, "error"); }
    e.target.value = "";
  });
}

function show(report) {
  $("#report-area").classList.remove("hidden");
  $("#rp-sub").textContent = `${report.report_id} · created ${new Date(report.created_at).toLocaleString()} · engine ${report.engine.version}`;
  $("#ex-json").onclick = () => exportReport(report, "json");
  $("#ex-csv").onclick = () => exportReport(report, "csv");
  $("#ex-html").onclick = () => exportReport(report, "html");
  $("#ex-print").onclick = printReport;
  const section = (title, ...content) => h("section", { class: "card" }, h("h2", { text: title }), ...content);
  $("#report-view").replaceChildren(
    summaryCard(report),
    section(`Findings (${report.findings.length})`, report.findings.length ? h("div", { class: "findings" }, report.findings.map(f => findingEl(f))) : h("p", { class: "muted", text: "No indicators matched. This does not mean the message is safe." })),
    section("Safer next steps", recommendationsEl(report.recommendations)),
    section("Links (not visited)", linksTable(report)),
    section("Sender & authentication claims", senderTable(report.sender), h("div", { class: "mt-14" }, authTable(report.headers.authentication)), h("h3", { class: "mt-18", text: "Received route" }), hopsTimeline(report.headers.received)),
    section("Attachments", attachmentsTable(report)),
    section("External threat intelligence", intelTable(report.intelligence?.results)),
    section("AI-assisted analysis", report.ai_analysis?.status === "completed" ? h("ul", { class: "stack small" }, report.ai_analysis.findings.map(f => h("li", {}, h("strong", { text: f.category.replace(/_/g, " ") + ": " }), h("q", { text: f.quote }), " — " + f.explanation))) : h("p", { class: "muted", text: report.ai_analysis?.note || "Not requested." })),
    section("Checks performed and not performed", h("div", { class: "grid grid-2" }, h("ul", { class: "feature-list small" }, report.checks.performed.map(t => h("li", { text: t }))), h("ul", { class: "feature-list no small" }, report.checks.not_performed.map(t => h("li", { text: t }))))),
    section("Limitations", h("ul", { class: "feature-list no small" }, report.limitations.map(t => h("li", { text: t }))))
  );
}
