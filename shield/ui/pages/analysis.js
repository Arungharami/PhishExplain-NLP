import { $, h, setStatus, chip } from "../dom.js";
import { getCurrent, setCurrent, getKey, setKey, isSaved, saveToHistory } from "../store.js";
import { summaryCard, findingsList, intelTable, highlighted } from "../render.js";
import { aiStatus, runAi } from "../api.js";

let cur = null;

export function init() {
  cur = getCurrent();
  if (!cur?.report) { $("#no-report").classList.remove("hidden"); return; }
  $("#analysis").classList.remove("hidden");
  const r = cur.report;
  $("#an-title").textContent = r.message.subject ? "“" + r.message.subject + "”" : "Current analysis";
  $("#an-sub").textContent = `${r.report_id} · ${new Date(r.created_at).toLocaleString()}`;
  $("#an-summary").replaceChildren(summaryCard(r, { compact: true }));
  $("#tier-observed").replaceChildren(findingsList(r.findings.filter(f => f.basis === "observed"), "No observed structural indicators."));
  $("#tier-heuristic").replaceChildren(findingsList(r.findings.filter(f => f.basis === "heuristic"), "No heuristic indicators."));
  $("#tier-intel").replaceChildren(intelTable(r.intelligence?.results));
  renderAi();
  setupText();
  setupAi();
}

function segments() { return cur.context?.segments || []; }

function setupText() {
  const sel = $("#seg-select");
  const segs = segments();
  if (!segs.length) { $("#marked").textContent = "Message text is not available for this analysis (for example, an imported JSON report). Findings above still include their evidence."; sel.classList.add("hidden"); return; }
  sel.replaceChildren(...segs.map((s, i) => h("option", { value: String(i), text: s.location.replace("header:", "Header: ").replace("body:", "Body: ") })));
  const bodyIdx = segs.findIndex(s => s.location.startsWith("body"));
  sel.value = String(bodyIdx >= 0 ? bodyIdx : 0);
  sel.addEventListener("change", drawText);
  drawText();
}

function drawText() {
  const seg = segments()[Number($("#seg-select").value)];
  if (!seg) return;
  const spans = (cur.report.language?.spans || []).filter(s => s.location === seg.location);
  const ai = cur.report.ai_analysis?.status === "completed" && cur.report.ai_analysis.location === seg.location ? cur.report.ai_analysis.findings.map(f => ({ start: f.start, end: f.end, category: f.category, ai: true })) : [];
  $("#marked").replaceChildren(highlighted(seg.text, [...spans, ...ai]));
}

function renderAi() {
  const ai = cur.report.ai_analysis;
  const host = $("#tier-ai");
  if (!ai || ai.status !== "completed") { host.replaceChildren(h("p", { class: "muted small", text: "Not run for this analysis." })); return; }
  host.replaceChildren(
    h("p", { class: "small" }, chip("Model: " + ai.model, "ai"), " ", chip("Prompt " + ai.prompt_version, "muted"), ai.rejected_ungrounded ? [" ", chip(ai.rejected_ungrounded + " ungrounded output(s) discarded", "warn")] : null),
    ai.context_summary ? h("p", { class: "small", text: ai.context_summary }) : null,
    ai.findings.length ? h("ul", { class: "stack small" }, ai.findings.map(f => h("li", {}, chip(f.category.replace(/_/g, " "), f.category === "possible_false_positive" ? "ok" : "ai"), " ", h("q", { text: f.quote }), " — ", f.explanation, " ", h("span", { class: "muted", text: `(${f.strength})` })))) : h("p", { class: "muted small", text: "The model returned no grounded findings." }),
    h("p", { class: "tiny muted", text: ai.note }));
}

async function setupAi() {
  const status = $("#ai-status");
  const { ok, data } = await aiStatus();
  if (!ok || !data.available) { setStatus(status, "AI analysis unavailable on this deployment" + (ok ? " (model provider or access control not configured)." : ".") + " The local analysis above is complete without it."); return; }
  const body = segments().find(s => s.location.startsWith("body"));
  if (!body) { setStatus(status, "AI analysis needs the message body, which is not available for this analysis."); return; }
  $("#ai-controls").classList.remove("hidden");
  $("#ai-key").value = getKey();
  const btn = $("#ai-run");
  $("#ai-consent").addEventListener("change", e => { btn.disabled = !e.target.checked; });
  btn.addEventListener("click", async () => {
    const key = $("#ai-key").value;
    if (!key) { setStatus(status, "Enter the Shield access key.", "error"); return; }
    setKey(key);
    const text = body.text.slice(0, data.max_chars || 12000);
    btn.disabled = true; setStatus(status, `Sending ${text.length.toLocaleString()} characters to ${data.provider} (${data.model})…`);
    const res = await runAi(text, key);
    btn.disabled = false;
    if (!res.ok) { setStatus(status, "AI analysis failed: " + (res.data?.error || "HTTP " + res.status) + ". Local results are unaffected.", "error"); return; }
    cur.report.ai_analysis = { ...res.data, location: body.location, requested_at: new Date().toISOString(), truncated: body.text.length > text.length };
    delete cur.report.ai_analysis.rate_limit;
    setCurrent(cur);
    if (isSaved(cur.report.report_id)) { try { saveToHistory(cur.report); } catch { /* ignore */ } }
    renderAi(); drawText();
    setStatus(status, `AI analysis completed: ${res.data.findings.length} grounded finding(s).`, "ok");
  });
}
