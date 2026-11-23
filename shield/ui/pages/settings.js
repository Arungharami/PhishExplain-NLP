import { $, h, setStatus, chip } from "../dom.js";
import { getSettings, setSettings, getKey, setKey, deleteAllData, listHistory } from "../store.js";
import { reputationStatus, aiStatus } from "../api.js";

export function init() {
  const s = getSettings(), status = $("#set-status");
  $("#set-history").checked = s.historyEnabled;
  $("#set-retention").value = String(s.retentionDays);
  $("#set-autosave").checked = s.autoSave;
  $("#set-autosave").disabled = !s.historyEnabled;
  $("#set-history").addEventListener("change", e => {
    if (!e.target.checked && listHistory().length && !confirm("Turn off local history and delete the saved analyses in this browser?")) { e.target.checked = true; return; }
    if (!e.target.checked) { try { localStorage.removeItem("pxs.history.v1"); } catch { /* ignore */ } }
    setSettings({ historyEnabled: e.target.checked, autoSave: e.target.checked ? getSettings().autoSave : false });
    $("#set-autosave").disabled = !e.target.checked; if (!e.target.checked) $("#set-autosave").checked = false;
    setStatus(status, e.target.checked ? "Local history enabled for this browser." : "Local history disabled and saved analyses deleted.", "ok");
  });
  $("#set-retention").addEventListener("change", e => { setSettings({ retentionDays: Number(e.target.value) }); listHistory(); setStatus(status, "Retention updated.", "ok"); });
  $("#set-autosave").addEventListener("change", e => { setSettings({ autoSave: e.target.checked }); setStatus(status, e.target.checked ? "Every completed scan will be saved." : "Scans are saved only when you choose.", "ok"); });

  $("#set-key").value = getKey();
  $("#key-save").addEventListener("click", () => { setKey($("#set-key").value.trim()); setStatus(status, "Access key kept for this tab session.", "ok"); });
  $("#key-clear").addEventListener("click", () => { setKey(""); $("#set-key").value = ""; setStatus(status, "Access key forgotten.", "ok"); });
  $("#delete-all").addEventListener("click", () => {
    if (!confirm("Delete all PhishExplain Shield data stored in this browser?")) return;
    deleteAllData();
    $("#set-history").checked = false; $("#set-autosave").checked = false; $("#set-key").value = "";
    setStatus(status, "All Shield data in this browser was deleted.", "ok");
  });
  loadStatus();
}

async function loadStatus() {
  const host = $("#svc-status");
  const [rep, ai] = await Promise.all([reputationStatus(), aiStatus()]);
  const line = (name, okFlag, detail) => h("div", { class: "row" }, h("strong", { text: name }), chip(okFlag ? "Available" : "Unavailable", okFlag ? "ok" : "muted"), h("span", { class: "muted", text: detail }));
  host.replaceChildren(
    line("Local scanner", true, "Runs in this browser."),
    rep.ok ? line("Reputation lookup", rep.data.available, `Providers configured: ${Object.entries(rep.data.providers).filter(([, v]) => v).map(([k]) => k.replace(/_/g, " ")).join(", ") || "none"} · access: ${rep.data.access.replace(/_/g, " ")} · durable rate limit: ${rep.data.durable_rate_limit ? "yes" : "no"}`) : line("Reputation lookup", false, rep.data?.error || "Service unreachable."),
    ai.ok ? line("AI analysis", ai.data.available, ai.data.available ? `${ai.data.provider} · ${ai.data.model} · prompt ${ai.data.prompt_version}` : "Model provider or access key not configured.") : line("AI analysis", false, ai.data?.error || "Service unreachable."),
    line("Accounts & cloud storage", false, "Not implemented."),
    line("Email provider integrations", false, "Not implemented."));
}
