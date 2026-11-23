// Shared helpers for Vercel Node functions.
import { timingSafeEqual, createHash } from "node:crypto";

export function send(res, code, data, extraHeaders = {}) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  return res.status(code).json(data);
}

/** Constant-time comparison of a supplied secret against the configured one. */
export function secretMatches(supplied, expected) {
  if (typeof supplied !== "string" || !supplied || typeof expected !== "string" || expected.length < 16) return false;
  const a = createHash("sha256").update(supplied).digest(), b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b) && supplied.length === expected.length;
}

export function clientId(req) {
  const fwd = String(req.headers?.["x-forwarded-for"] || "").split(",")[0].trim();
  const ip = String(req.headers?.["x-real-ip"] || fwd || req.socket?.remoteAddress || "unknown");
  // Store only a hash of the IP in rate-limit keys.
  return createHash("sha256").update("pxs:" + ip).digest("hex").slice(0, 24);
}

/** Parse a JSON body with a hard byte limit. Returns {ok, body, error, status}. */
export function readJson(req, maxBytes) {
  const declared = Number(req.headers?.["content-length"] || 0);
  if (declared > maxBytes) return { ok: false, status: 413, error: "Request too large" };
  const ct = String(req.headers?.["content-type"] || "");
  if (!ct.toLowerCase().startsWith("application/json")) return { ok: false, status: 415, error: "Content-Type must be application/json" };
  let body = req.body;
  if (typeof body === "string") {
    if (Buffer.byteLength(body) > maxBytes) return { ok: false, status: 413, error: "Request too large" };
    try { body = JSON.parse(body); } catch { return { ok: false, status: 400, error: "Invalid JSON" }; }
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return { ok: false, status: 400, error: "Expected a JSON object" };
  if (Buffer.byteLength(JSON.stringify(body)) > maxBytes) return { ok: false, status: 413, error: "Request too large" };
  return { ok: true, body };
}

/** Allow only same-origin browser calls (or non-browser clients without an Origin header). */
export function originAllowed(req) {
  const origin = req.headers?.origin;
  if (!origin) return true;
  const host = req.headers?.["x-forwarded-host"] || req.headers?.host;
  try { return new URL(origin).host === host; } catch { return false; }
}
