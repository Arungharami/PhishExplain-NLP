// POST /api/reputation — optional, consent-based URL reputation lookups via allow-listed providers.
// GET  /api/reputation — configuration status (never returns secrets).
import { send, secretMatches, clientId, readJson, originAllowed } from "../lib/http.js";
import { hit, limiterConfig } from "../lib/ratelimit.js";
import { lookupUrls, configuredProviders, MAX_URLS_PER_REQUEST } from "../lib/reputation.js";

const PER_CLIENT_PER_HOUR = 30;

function accessMode(env) {
  if (env.SHIELD_REPUTATION_PUBLIC === "true" && limiterConfig(env).durable) return "public_rate_limited";
  if (env.SHIELD_ACCESS_KEY && env.SHIELD_ACCESS_KEY.length >= 16) return "access_key_required";
  return "disabled";
}

export default async function handler(req, res, { env = process.env, fetchImpl = fetch } = {}) {
  const providers = configuredProviders(env);
  const anyProvider = Object.values(providers).some(Boolean);
  if (req.method === "GET") {
    return send(res, 200, { service: "reputation", available: anyProvider && accessMode(env) !== "disabled", providers, access: accessMode(env), durable_rate_limit: limiterConfig(env).durable, max_urls_per_request: MAX_URLS_PER_REQUEST });
  }
  if (req.method !== "POST") return send(res, 405, { error: "Method not allowed" }, { Allow: "GET, POST" });
  if (!originAllowed(req)) return send(res, 403, { error: "Cross-origin requests are not allowed" });
  if (!anyProvider) return send(res, 503, { status: "unavailable", error: "Reputation lookup unavailable — no provider is configured on this deployment." });
  const mode = accessMode(env);
  const keyOk = secretMatches(req.headers?.["x-shield-key"], env.SHIELD_ACCESS_KEY);
  if (mode === "disabled") return send(res, 503, { status: "unavailable", error: "Reputation lookup unavailable — access control is not configured." });
  if (mode === "access_key_required" && !keyOk) return send(res, 401, { error: "Shield access key required" });

  const parsed = readJson(req, 24 * 1024);
  if (!parsed.ok) return send(res, parsed.status, { error: parsed.error });
  const { urls, consent } = parsed.body;
  if (consent !== true) return send(res, 400, { error: "Explicit consent is required: URLs are sent to third-party providers." });
  if (!Array.isArray(urls) || !urls.length || urls.length > MAX_URLS_PER_REQUEST || urls.some(u => typeof u !== "string")) return send(res, 400, { error: `Supply 1–${MAX_URLS_PER_REQUEST} URL strings` });
  if (Object.keys(parsed.body).some(k => !["urls", "consent"].includes(k))) return send(res, 400, { error: "Unexpected fields" });

  const who = keyOk ? "key" : clientId(req);
  const perClient = await hit("rep:" + who, PER_CLIENT_PER_HOUR, 3600, { env, fetchImpl });
  const daily = await hit("rep:global", Number(env.SHIELD_REPUTATION_DAILY_LIMIT || 300), 86400, { env, fetchImpl });
  if (!perClient.allowed || !daily.allowed) return send(res, 429, { error: perClient.error || daily.error ? "Rate limiter unavailable" : "Rate limit exceeded", retry_after_seconds: Math.min(perClient.reset_seconds, daily.reset_seconds) }, { "Retry-After": String(Math.min(perClient.reset_seconds, daily.reset_seconds)) });

  const begin = Date.now();
  const out = await lookupUrls([...new Set(urls)], { env, fetchImpl });
  const statuses = out.checks.flatMap(c => c.results.map(r => r.status));
  const failures = statuses.filter(s => s === "unavailable").length;
  // Operational log without URLs or user content.
  console.log(JSON.stringify({ evt: "reputation_lookup", urls: urls.length, providers: out.providers_enabled, failures, ms: Date.now() - begin }));
  return send(res, 200, { status: failures ? "partial" : "completed", ...out, latency_ms: Date.now() - begin, rate_limit: { durable: perClient.durable, remaining_hour: Math.max(0, perClient.limit - (perClient.count || 0)) }, note: "Only listed/flagged statuses come from providers. 'not_listed' means no provider record at lookup time; it is not a safety verdict." });
}
