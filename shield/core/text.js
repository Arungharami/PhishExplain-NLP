// Text utilities shared by the browser UI and Node tests.
// Nothing here executes, renders, or fetches email content: HTML is handled as an inert string.

const NAMED_ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", copy: "©", reg: "®", hellip: "…", ndash: "–", mdash: "—", lsquo: "‘", rsquo: "’", ldquo: "“", rdquo: "”", zwnj: "‌", zwj: "‍", shy: "­" };

/** Decode HTML character references without using the DOM (works identically in Node and browsers). */
export function decodeEntities(value) {
  return String(value ?? "").replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z][a-z0-9]{1,31});?/gi, (whole, ref) => {
    if (ref[0] === "#") {
      const code = ref[1] === "x" || ref[1] === "X" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return "�";
      return String.fromCodePoint(code);
    }
    const named = NAMED_ENTITIES[ref.toLowerCase()];
    return named ?? whole;
  });
}

/**
 * Convert an HTML email part into visible-ish plain text for language analysis.
 * Removes script/style/head/comment content, converts block tags to newlines and strips all other tags.
 * This is a static string transformation; the HTML is never parsed into a live document.
 */
export function htmlToText(html) {
  let s = String(html ?? "");
  s = s.replace(/<!--[\s\S]*?-->/g, " ");
  s = s.replace(/<(script|style|head|title|template|noscript)\b[\s\S]*?<\/\1\s*>/gi, " ");
  s = s.replace(/<(br|\/p|\/div|\/li|\/tr|\/h[1-6]|\/table|p|div|li|tr|h[1-6])\b[^>]*>/gi, "\n");
  s = s.replace(/<[^>]*>/g, " ");
  s = decodeEntities(s);
  s = s.replace(/[​-‍⁠﻿­]/g, "");
  s = s.replace(/[ \t ]+/g, " ").replace(/ *\n */g, "\n").replace(/\n{3,}/g, "\n\n");
  return s.trim();
}

export const collapse = s => String(s ?? "").replace(/\s+/g, " ").trim();
export const truncate = (s, n = 160) => { const t = String(s ?? ""); return t.length > n ? t.slice(0, n - 1) + "…" : t; };

/** Return a short excerpt around [start,end) of text, with the exact match preserved. */
export function excerpt(text, start, end, pad = 48) {
  const a = Math.max(0, start - pad), b = Math.min(text.length, end + pad);
  return (a > 0 ? "…" : "") + collapse(text.slice(a, start)) + (a < start ? " " : "") + "«" + text.slice(start, end) + "»" + (end < b ? " " : "") + collapse(text.slice(end, b)) + (b < text.length ? "…" : "");
}

// RFC 3492 punycode decoder (used only for displaying IDN hostnames; never for resolution).
const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;
function adapt(delta, numPoints, firstTime) {
  let k = 0; delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1; delta += Math.floor(delta / numPoints);
  for (; delta > ((BASE - TMIN) * TMAX) >> 1; k += BASE) delta = Math.floor(delta / (BASE - TMIN));
  return Math.floor(k + ((BASE - TMIN + 1) * delta) / (delta + SKEW));
}
function basicToDigit(cp) { if (cp - 48 < 10) return cp - 22; if (cp - 65 < 26) return cp - 65; if (cp - 97 < 26) return cp - 97; return BASE; }
export function punycodeDecode(input) {
  const output = []; let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
  let basic = input.lastIndexOf("-"); if (basic < 0) basic = 0;
  for (let j = 0; j < basic; ++j) { if (input.charCodeAt(j) >= 0x80) throw new RangeError("Invalid punycode"); output.push(input.charCodeAt(j)); }
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new RangeError("Invalid punycode");
      const digit = basicToDigit(input.charCodeAt(index++));
      if (digit >= BASE) throw new RangeError("Invalid punycode");
      i += digit * w; const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break; w *= BASE - t;
      if (w > 0x7fffffff) throw new RangeError("Punycode overflow");
    }
    const out = output.length + 1; bias = adapt(i - oldi, out, oldi === 0); n += Math.floor(i / out); i %= out;
    if (n > 0x10ffff) throw new RangeError("Punycode overflow");
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}
/** Convert an ASCII (xn--) hostname into its Unicode display form. Returns the input on failure. */
export function hostnameToUnicode(host) {
  try { return String(host).split(".").map(l => /^xn--/i.test(l) ? punycodeDecode(l.slice(4).toLowerCase()) : l).join("."); }
  catch { return host; }
}

/** Identify Unicode scripts in a string (coarse; enough to flag mixed-script hostnames). */
export function scriptsIn(s) {
  const found = new Set();
  for (const ch of String(s)) {
    if (/[a-z]/i.test(ch)) found.add("Latin");
    else if (/\p{Script=Cyrillic}/u.test(ch)) found.add("Cyrillic");
    else if (/\p{Script=Greek}/u.test(ch)) found.add("Greek");
    else if (/\p{Script=Armenian}/u.test(ch)) found.add("Armenian");
    else if (/\p{Script=Latin}/u.test(ch)) found.add("Latin");
    else if (/[\p{L}]/u.test(ch)) found.add("Other");
  }
  return [...found];
}

/** Levenshtein distance with an early-exit bound. */
export function editDistance(a, b, max = 3) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev2 = null, prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i]; let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      // adjacent transposition (optimal string alignment distance)
      if (prev2 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) cur[j] = Math.min(cur[j], prev2[j - 2] + 1);
      rowMin = Math.min(rowMin, cur[j]);
    }
    if (rowMin > max) return max + 1;
    prev2 = prev; prev = cur;
  }
  return prev[b.length];
}
