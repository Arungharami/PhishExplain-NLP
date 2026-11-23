// Server-side URL reputation adapter with one normalized response schema.
//
// SECURITY: the URLs being checked are NEVER fetched, resolved or followed. They are only sent as
// query data to fixed, allow-listed provider API origins. Every outbound request goes through
// providerFetch(), which rejects any other origin and refuses redirects.
//
// Provider terms (verified 2026-11-23; re-check before production use):
// - Google Safe Browsing v5 urls:search — non-commercial use only (Web Risk API for commercial);
//   urls:search sends full URLs to Google.
// - URLhaus API — requires a free abuse.ch Auth-Key.
// - VirusTotal API v3 (lookup only, never submission) — public API is non-commercial, 4 req/min, 500/day.
import { createHash } from "node:crypto";

export const PROVIDER_ORIGINS = Object.freeze({
  google_safe_browsing: "https://safebrowsing.googleapis.com",
  urlhaus: "https://urlhaus-api.abuse.ch",
  virustotal: "https://www.virustotal.com"
});
const ALLOWED_ORIGINS = new Set(Object.values(PROVIDER_ORIGINS));
export const MAX_URLS_PER_REQUEST = 10;
const cache = new Map();

export function providerFetch(target, init = {}, fetchImpl = fetch) {
  const u = new URL(target);
  if (!ALLOWED_ORIGINS.has(u.origin)) throw new Error("Blocked outbound request to non-allow-listed origin " + u.origin);
  return fetchImpl(u.href, { ...init, redirect: "error", signal: AbortSignal.timeout(8000) });
}

export function configuredProviders(env = process.env) {
  return {
    google_safe_browsing: Boolean(env.GOOGLE_SAFE_BROWSING_API_KEY),
    urlhaus: Boolean(env.URLHAUS_AUTH_KEY),
    virustotal: Boolean(env.VIRUSTOTAL_API_KEY)
  };
}

const PRIVATE_HOST = /^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.lan|.*\.home\.arpa)$/i;
function isPrivateHost(host) {
  const h = host.replace(/^\[|\]$/g, "");
  if (PRIVATE_HOST.test(h)) return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const [a, b] = h.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  if (h.includes(":")) return /^(::1|::|fc|fd|fe80)/i.test(h);
  return !h.includes(".");
}

/** Validate and normalize a URL for lookup. Strips credentials and fragments (never sent to providers). */
export function normalizeForLookup(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 2048) return { ok: false, reason: "URL must be a non-empty string up to 2048 characters" };
  let u;
  try { u = new URL(value.trim()); } catch { return { ok: false, reason: "Not a valid absolute URL" }; }
  if (!["http:", "https:"].includes(u.protocol)) return { ok: false, reason: "Only http and https URLs can be checked" };
  if (isPrivateHost(u.hostname)) return { ok: false, reason: "Private, local or single-label hosts are not sent to external providers" };
  u.username = ""; u.password = ""; u.hash = "";
  return { ok: true, url: u.href, stripped_credentials: value.includes("@") && /\/\/[^/]*@/.test(value) };
}

const vtId = url => Buffer.from(url).toString("base64url");
const cacheKey = (p, url) => p + ":" + createHash("sha256").update(url).digest("hex");

function result(provider, url, status, summary, extra = {}) {
  return { provider, query_type: "url", query: url, status, summary, verdict_source: provider, provider_labels: extra.labels || [], details: extra.details || null, checked_at: new Date().toISOString(), cache_age_seconds: 0, reference: extra.reference || null };
}

async function checkGsb(url, env, fetchImpl) {
  const q = new URLSearchParams(); q.append("urls", url); q.append("key", env.GOOGLE_SAFE_BROWSING_API_KEY);
  const res = await providerFetch(PROVIDER_ORIGINS.google_safe_browsing + "/v5/urls:search?" + q, { method: "GET", headers: { Accept: "application/json" } }, fetchImpl);
  if (!res.ok) return { r: result("google_safe_browsing", url, "unavailable", `Provider returned HTTP ${res.status}`), ttl: 0 };
  const data = await res.json();
  const threats = Array.isArray(data?.threats) ? data.threats : [];
  const ttl = Math.min(86400, Math.max(0, parseFloat(String(data?.cacheDuration || "300").replace(/s$/, "")) || 300));
  if (!threats.length) return { r: result("google_safe_browsing", url, "not_listed", "No match in Google Safe Browsing lists at lookup time (this is not a safety guarantee)."), ttl };
  const types = [...new Set(threats.flatMap(t => t.threatTypes || []))];
  return { r: result("google_safe_browsing", url, "listed", "Listed by Google Safe Browsing: " + types.join(", "), { labels: types, details: { matched: threats.map(t => ({ url: t.url, threat_types: t.threatTypes })) }, reference: "https://transparencyreport.google.com/safe-browsing/search" }), ttl };
}

async function checkUrlhaus(url, env, fetchImpl) {
  const res = await providerFetch(PROVIDER_ORIGINS.urlhaus + "/v1/url/", { method: "POST", headers: { "Auth-Key": env.URLHAUS_AUTH_KEY, "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, body: new URLSearchParams({ url }).toString() }, fetchImpl);
  if (!res.ok) return { r: result("urlhaus", url, "unavailable", `Provider returned HTTP ${res.status}`), ttl: 0 };
  const data = await res.json();
  if (data?.query_status === "no_results") return { r: result("urlhaus", url, "not_listed", "Not present in the URLhaus malware-URL database (this is not a safety guarantee)."), ttl: 1800 };
  if (data?.query_status === "ok") {
    const labels = [data.threat, ...(data.tags || [])].filter(Boolean);
    return { r: result("urlhaus", url, "listed", `Listed by URLhaus as ${data.threat || "malicious URL"} (status: ${data.url_status || "unknown"}, added ${data.date_added || "unknown"})`, { labels, details: { url_status: data.url_status, date_added: data.date_added, threat: data.threat, tags: data.tags || [] }, reference: data.urlhaus_reference || null }), ttl: 1800 };
  }
  return { r: result("urlhaus", url, "unavailable", "Provider response: " + String(data?.query_status || "unknown").slice(0, 60)), ttl: 0 };
}

async function checkVirusTotal(url, env, fetchImpl) {
  const res = await providerFetch(PROVIDER_ORIGINS.virustotal + "/api/v3/urls/" + vtId(url), { method: "GET", headers: { "x-apikey": env.VIRUSTOTAL_API_KEY, Accept: "application/json" } }, fetchImpl);
  if (res.status === 404) return { r: result("virustotal", url, "no_record", "VirusTotal has no existing analysis of this exact URL. Shield does not submit URLs for scanning."), ttl: 1800 };
  if (!res.ok) return { r: result("virustotal", url, "unavailable", `Provider returned HTTP ${res.status}${res.status === 429 ? " (quota exceeded)" : ""}`), ttl: 0 };
  const data = await res.json();
  const a = data?.data?.attributes || {};
  const s = a.last_analysis_stats || {};
  const total = ["malicious", "suspicious", "harmless", "undetected", "timeout"].reduce((n, k) => n + (Number(s[k]) || 0), 0);
  const when = a.last_analysis_date ? new Date(a.last_analysis_date * 1000).toISOString() : null;
  const details = { last_analysis_stats: s, last_analysis_date: when };
  const ref = "https://www.virustotal.com/gui/url/" + createHash("sha256").update(url).digest("hex");
  if ((s.malicious || 0) > 0 || (s.suspicious || 0) > 0) return { r: result("virustotal", url, "flagged", `${s.malicious || 0} malicious and ${s.suspicious || 0} suspicious verdicts out of ${total} vendors in VirusTotal's last analysis (${when || "date unknown"}).`, { labels: ["malicious:" + (s.malicious || 0), "suspicious:" + (s.suspicious || 0)], details, reference: ref }), ttl: 1800 };
  return { r: result("virustotal", url, "not_listed", `No vendor flagged this URL in VirusTotal's last analysis (${when || "date unknown"}). Not a safety guarantee.`, { details, reference: ref }), ttl: 1800 };
}

const CHECKERS = { google_safe_browsing: checkGsb, urlhaus: checkUrlhaus, virustotal: checkVirusTotal };

/** Look up URLs with every configured provider. Never throws for provider failures. */
export async function lookupUrls(urls, { env = process.env, fetchImpl = fetch, now = Date.now() } = {}) {
  const providers = configuredProviders(env);
  const enabled = Object.keys(CHECKERS).filter(p => providers[p]);
  const out = [];
  for (const raw of urls) {
    const norm = normalizeForLookup(raw);
    if (!norm.ok) { out.push({ input: String(raw).slice(0, 300), ok: false, reason: norm.reason, results: [] }); continue; }
    const rows = [];
    for (const p of Object.keys(CHECKERS)) {
      if (!providers[p]) { rows.push(result(p, norm.url, "not_configured", "Provider credentials are not configured on this deployment.")); continue; }
      const key = cacheKey(p, norm.url);
      const hitc = cache.get(key);
      if (hitc && hitc.expires > now) { rows.push({ ...hitc.r, cache_age_seconds: Math.round((now - hitc.stored) / 1000) }); continue; }
      try {
        const { r, ttl } = await CHECKERS[p](norm.url, env, fetchImpl);
        if (ttl > 0) cache.set(key, { r, stored: now, expires: now + ttl * 1000 });
        rows.push(r);
      } catch (err) {
        rows.push(result(p, norm.url, "unavailable", err?.name === "TimeoutError" ? "Provider timed out" : "Provider request failed"));
      }
    }
    out.push({ input: String(raw).slice(0, 300), ok: true, queried_url: norm.url, credentials_stripped: norm.stripped_credentials, results: rows });
  }
  return { providers_enabled: enabled, checks: out };
}

export function _clearCache() { cache.clear(); }
