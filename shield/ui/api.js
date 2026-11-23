// Client for the optional server endpoints. Same-origin only; the access key is sent in a header.
async function call(path, { method = "GET", body, key } = {}) {
  const headers = { Accept: "application/json" };
  if (body) headers["Content-Type"] = "application/json";
  if (key) headers["x-shield-key"] = key;
  let res;
  try { res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined, cache: "no-store", credentials: "same-origin", redirect: "error" }); }
  catch { return { ok: false, status: 0, data: { error: "Service unreachable (offline, or not deployed in this environment)." } }; }
  let data = null;
  try { data = await res.json(); } catch { data = { error: `Unexpected response (HTTP ${res.status})` }; }
  return { ok: res.ok, status: res.status, data };
}
export const reputationStatus = () => call("/api/reputation");
export const aiStatus = () => call("/api/ai-analysis");
export const runReputation = (urls, key) => call("/api/reputation", { method: "POST", body: { urls, consent: true }, key });
export const runAi = (text, key) => call("/api/ai-analysis", { method: "POST", body: { text, consent: true }, key });
