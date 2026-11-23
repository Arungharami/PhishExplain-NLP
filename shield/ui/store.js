// Browser-only persistence.
// - The current analysis lives in sessionStorage (cleared when the tab closes).
// - History is OFF by default and stored in localStorage only after explicit opt-in.
// - The access key is kept in sessionStorage only and never written into reports.
const K = { current: "pxs.current.v1", settings: "pxs.settings.v1", history: "pxs.history.v1", key: "pxs.key.v1" };

export const STATUSES = Object.freeze([
  { id: "new", label: "New" },
  { id: "under_review", label: "Under review" },
  { id: "needs_verification", label: "Needs verification" },
  { id: "reported", label: "Reported" },
  { id: "resolved", label: "Resolved" }
]);
const DEFAULT_SETTINGS = { historyEnabled: false, retentionDays: 30, autoSave: false, consentedAt: null };

function read(storage, key, fallback) {
  try { const raw = storage.getItem(key); return raw ? JSON.parse(raw) : fallback; } catch { return fallback; }
}
function write(storage, key, value) {
  try { storage.setItem(key, JSON.stringify(value)); return true; } catch { return false; }
}

export function getSettings() { return { ...DEFAULT_SETTINGS, ...read(localStorage, K.settings, {}) }; }
export function setSettings(patch) {
  const next = { ...getSettings(), ...patch };
  if (patch.historyEnabled === true && !getSettings().historyEnabled) next.consentedAt = new Date().toISOString();
  if (patch.historyEnabled === false) next.consentedAt = null;
  write(localStorage, K.settings, next);
  return next;
}

export function getCurrent() { return read(sessionStorage, K.current, null); }
export function setCurrent(value) { return write(sessionStorage, K.current, value); }
export function clearCurrent() { try { sessionStorage.removeItem(K.current); } catch { /* ignore */ } }

export function getKey() { try { return sessionStorage.getItem(K.key) || ""; } catch { return ""; } }
export function setKey(v) { try { if (v) sessionStorage.setItem(K.key, v); else sessionStorage.removeItem(K.key); } catch { /* ignore */ } }

export function listHistory() {
  purgeExpired();
  const items = read(localStorage, K.history, []);
  return Array.isArray(items) ? items : [];
}
function saveAll(items) { return write(localStorage, K.history, items); }

/** Save a report (never the full message text) to local history. Requires history to be enabled. */
export function saveToHistory(report) {
  if (!getSettings().historyEnabled) throw new Error("Local history is disabled. Enable it in Settings first.");
  const items = read(localStorage, K.history, []);
  const now = new Date().toISOString();
  const existing = items.find(x => x.report.report_id === report.report_id);
  if (existing) { existing.report = report; existing.updated_at = now; }
  else items.unshift({ report, status: "new", notes: [], saved_at: now, updated_at: now });
  if (!saveAll(items.slice(0, 500))) throw new Error("Browser storage is full or unavailable.");
  return true;
}
export function isSaved(reportId) { return read(localStorage, K.history, []).some(x => x.report.report_id === reportId); }
export function updateHistory(reportId, patch) {
  const items = read(localStorage, K.history, []);
  const item = items.find(x => x.report.report_id === reportId);
  if (!item) return false;
  Object.assign(item, patch, { updated_at: new Date().toISOString() });
  return saveAll(items);
}
export function addNote(reportId, text) {
  const items = read(localStorage, K.history, []);
  const item = items.find(x => x.report.report_id === reportId);
  if (!item) return false;
  item.notes.push({ at: new Date().toISOString(), text: String(text).slice(0, 2000) });
  item.updated_at = new Date().toISOString();
  return saveAll(items);
}
export function removeFromHistory(reportId) { return saveAll(read(localStorage, K.history, []).filter(x => x.report.report_id !== reportId)); }
export function purgeExpired() {
  const days = Number(getSettings().retentionDays);
  if (!days) return;
  const cutoff = Date.now() - days * 86400000;
  const items = read(localStorage, K.history, []);
  if (!Array.isArray(items)) return;
  const kept = items.filter(x => Date.parse(x.updated_at || x.saved_at) >= cutoff);
  if (kept.length !== items.length) saveAll(kept);
}
export function deleteAllData() {
  for (const k of Object.values(K)) { try { localStorage.removeItem(k); sessionStorage.removeItem(k); } catch { /* ignore */ } }
}
