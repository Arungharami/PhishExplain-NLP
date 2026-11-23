// POST /api/ai-analysis — optional contextual model analysis (consent + access key + rate limits).
// GET  /api/ai-analysis — configuration status (never returns secrets).
import { send, secretMatches, readJson, originAllowed } from "../lib/http.js";
import { hit, limiterConfig } from "../lib/ratelimit.js";
import { aiConfigured, aiModel, runAiAnalysis, AI_MAX_CHARS, AI_PROMPT_VERSION } from "../lib/ai.js";

export default async function handler(req, res, { env = process.env, fetchImpl = fetch } = {}) {
  const keySet = Boolean(env.SHIELD_ACCESS_KEY && env.SHIELD_ACCESS_KEY.length >= 16);
  const configured = aiConfigured(env) && keySet;
  if (req.method === "GET") return send(res, 200, { service: "ai-analysis", available: configured, provider: configured ? "openai" : null, model: configured ? aiModel(env) : null, prompt_version: AI_PROMPT_VERSION, access: keySet ? "access_key_required" : "disabled", durable_rate_limit: limiterConfig(env).durable, max_chars: AI_MAX_CHARS });
  if (req.method !== "POST") return send(res, 405, { error: "Method not allowed" }, { Allow: "GET, POST" });
  if (!originAllowed(req)) return send(res, 403, { error: "Cross-origin requests are not allowed" });
  if (!configured) return send(res, 503, { status: "unavailable", error: "AI analysis unavailable — model provider or access control not configured. The local scanner still works." });
  if (!secretMatches(req.headers?.["x-shield-key"], env.SHIELD_ACCESS_KEY)) return send(res, 401, { error: "Shield access key required" });

  const parsed = readJson(req, 64 * 1024);
  if (!parsed.ok) return send(res, parsed.status, { error: parsed.error });
  const { text, consent } = parsed.body;
  if (Object.keys(parsed.body).some(k => !["text", "consent"].includes(k))) return send(res, 400, { error: "Unexpected fields" });
  if (consent !== true) return send(res, 400, { error: "Explicit consent is required: message text is sent to a third-party model provider." });
  if (typeof text !== "string" || !text.trim() || text.length > AI_MAX_CHARS) return send(res, 400, { error: `Supply text of 1–${AI_MAX_CHARS} characters` });

  const hourly = await hit("ai:key", Number(env.SHIELD_AI_HOURLY_LIMIT || 30), 3600, { env, fetchImpl });
  const daily = await hit("ai:global", Number(env.SHIELD_AI_DAILY_LIMIT || 100), 86400, { env, fetchImpl });
  if (!hourly.allowed || !daily.allowed) return send(res, 429, { error: hourly.error || daily.error ? "Rate limiter unavailable" : "AI usage limit reached", retry_after_seconds: Math.min(hourly.reset_seconds, daily.reset_seconds) }, { "Retry-After": String(Math.min(hourly.reset_seconds, daily.reset_seconds)) });

  try {
    const out = await runAiAnalysis(text, { env, fetchImpl });
    // Cost monitoring: token usage only — never message content.
    console.log(JSON.stringify({ evt: "ai_analysis", ok: out.ok, model: out.data?.model || aiModel(env), usage: out.data?.usage || null, rejected: out.data?.rejected_ungrounded ?? null, daily_count: daily.count, durable: daily.durable }));
    if (!out.ok) return send(res, out.status, { status: "error", error: out.error, provider_status: out.provider_status ?? null });
    return send(res, 200, { ...out.data, rate_limit: { durable: hourly.durable, daily_used: daily.count, daily_limit: daily.limit } });
  } catch (err) {
    return send(res, 502, { status: "error", error: err?.name === "TimeoutError" ? "Model provider timed out" : "AI analysis failed" });
  }
}
