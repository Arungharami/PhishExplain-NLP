import { analyzeEmail } from "../../core/analyze.js";
import { $, setStatus } from "../dom.js";
import { getCurrent } from "../store.js";
import { senderTable, authTable, hopsTimeline, findingsList } from "../render.js";

export function init() {
  const status = $("#hdr-status");
  $("#hdr-analyze").addEventListener("click", async () => {
    let text = $("#header-input").value;
    if (!text.trim()) { setStatus(status, "Paste the raw headers first.", "error"); return; }
    if (!/\n\s*\n/.test(text.replace(/\r\n/g, "\n"))) text = text.replace(/\s+$/, "") + "\n\n"; // headers-only paste
    try {
      const { report } = await analyzeEmail(text, { source: "paste" });
      if (report.input.kind !== "raw_message") { setStatus(status, "No header block was recognized. Paste headers starting at the first line (for example Received: or From:).", "error"); return; }
      render(report);
      setStatus(status, `Parsed ${report.message.parts.headers} header(s) and ${report.headers.received.length} Received hop(s) locally.`, "ok");
    } catch (err) { setStatus(status, "Could not parse headers: " + err.message, "error"); }
  });
  $("#hdr-current").addEventListener("click", () => {
    const cur = getCurrent();
    if (!cur?.report) { setStatus(status, "No current scan in this tab.", "error"); return; }
    if (!cur.report.message.parts.headers) { setStatus(status, "The current scan had no headers. Paste the full original message in the scanner.", "error"); return; }
    render(cur.report);
    setStatus(status, "Showing headers from the current scan.", "ok");
  });
  if (getCurrent()?.report?.message?.parts?.headers) setStatus(status, "Your current scan includes headers. Select “Use current scan”.");
}

function render(report) {
  $("#hdr-results").classList.remove("hidden");
  $("#hdr-sender").replaceChildren(senderTable(report.sender));
  $("#hdr-auth").replaceChildren(authTable(report.headers.authentication));
  $("#hdr-hops").replaceChildren(hopsTimeline(report.headers.received));
  $("#hdr-findings").replaceChildren(findingsList(report.findings.filter(f => f.category === "sender" || f.category === "header"), "No sender or header indicators matched."));
}
