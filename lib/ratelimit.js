// Fixed-window rate limiting and daily usage budgets.
// Durable when an Upstash Redis REST endpoint is configured (UPSTASH_REDIS_REST_URL/TOKEN, or the
// Vercel KV equivalents KV_REST_API_URL/TOKEN). Otherwise falls back to per-instance memory and
// reports durable:false so callers can refuse public access.
const memory = new Map();

export function limiterConfig(env = process.env) {
  const url = env.UPSTASH_REDIS_REST_URL || env.KV_REST_API_URL || "";
  const token = env.UPSTASH_REDIS_REST_TOKEN || env.KV_REST_API_TOKEN || "";
  let valid = false;
  try { const u = new URL(url); valid = u.protocol === "https:" && Boolean(token); } catch { valid = false; }
  return { durable: valid, url: valid ? url.replace(/\/$/, "") : null, token: valid ? token : null };
}

async function redisIncr(cfg, key, windowSeconds, fetchImpl) {
  const res = await fetchImpl(cfg.url + "/pipeline", {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(3000),
    headers: { Authorization: "Bearer " + cfg.token, "Content-Type": "application/json" },
    body: JSON.stringify([["INCR", key], ["EXPIRE", key, String(windowSeconds), "NX"]])
  });
  if (!res.ok) throw new Error("Rate-limit store unavailable");
  const data = await res.json();
  const n = Number(data?.[0]?.result);
  if (!Number.isFinite(n)) throw new Error("Rate-limit store returned invalid data");
  return n;
}

/**
 * Count one event for `key` in a fixed window. Returns {allowed, count, limit, durable, reset_seconds}.
 * If the durable store errors, the request is refused (fail closed).
 */
export async function hit(key, limit, windowSeconds, { env = process.env, fetchImpl = fetch, now = Date.now() } = {}) {
  const cfg = limiterConfig(env);
  const windowId = Math.floor(now / 1000 / windowSeconds);
  const fullKey = `pxs:rl:${key}:${windowId}`;
  const reset = windowSeconds - Math.floor(now / 1000) % windowSeconds;
  if (cfg.durable) {
    try {
      const count = await redisIncr(cfg, fullKey, windowSeconds, fetchImpl);
      return { allowed: count <= limit, count, limit, durable: true, reset_seconds: reset };
    } catch {
      return { allowed: false, count: null, limit, durable: true, reset_seconds: reset, error: "rate_limit_store_unavailable" };
    }
  }
  for (const [k, v] of memory) if (v.expires < now) memory.delete(k);
  const entry = memory.get(fullKey) || { count: 0, expires: now + windowSeconds * 1000 };
  entry.count++;
  memory.set(fullKey, entry);
  return { allowed: entry.count <= limit, count: entry.count, limit, durable: false, reset_seconds: reset };
}

export function _resetMemory() { memory.clear(); }
