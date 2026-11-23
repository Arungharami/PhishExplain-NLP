// URL extraction and structural inspection. URLs are parsed as strings only:
// nothing is fetched, resolved, followed or rendered.
import { decodeEntities, collapse, truncate } from "./text.js";
import { domainInfo, lookalike, URL_SHORTENERS, sameOrganization, isBrandDomain } from "./domains.js";
import { makeFinding } from "./rules.js";

export const MAX_URLS = 200;
export const MAX_FORMS = 10;
const TEXT_URL = /\b(?:https?:\/\/|www\.)[^\s<>"'\u201c\u201d\u2018\u2019`{}|\\^\[\]]+/gi;
const TRAILING = /[)\].,;:!?'"\u201d\u2019>]+$/;

/** Extract http(s)/www URLs from plain text with their offsets. */
export function extractTextUrls(text, location) {
  const out = [];
  if (!text) return out;
  for (const m of String(text).matchAll(TEXT_URL)) {
    let value = m[0];
    // Keep balanced parentheses (e.g. Wikipedia links) but strip trailing punctuation.
    while (TRAILING.test(value)) {
      const last = value.at(-1);
      if (last === ")" && (value.match(/\(/g) || []).length >= (value.match(/\)/g) || []).length) break;
      value = value.slice(0, -1);
    }
    if (value.length < 8) continue;
    out.push({ raw: value, location, offset: m.index, display_text: null });
    if (out.length >= MAX_URLS) break;
  }
  return out;
}

const attr = (tag, name) => {
  const m = tag.match(new RegExp("\\s" + name + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'=<>`]+))", "i"));
  return m ? decodeEntities(m[1] ?? m[2] ?? m[3] ?? "").trim() : null;
};

/**
 * Extract link targets from an HTML string without building a DOM.
 * Returns anchors (href + visible text), area/form targets and dangerous schemes.
 */
export function extractHtmlLinks(html, location = "body:html") {
  const out = [], forms = [];
  if (!html) return { links: out, forms };
  const src = String(html).replace(/<!--[\s\S]*?-->/g, " ");
  // Find start tags first, then take visible text up to </a> (or the next <a) within 2,000 chars,
  // so unclosed anchors — common in malformed phishing HTML — still yield their href. Linear time.
  for (const m of src.matchAll(/<a\b([^>]*)>/gi)) {
    const href = attr(m[1], "href");
    if (!href) continue;
    const after = m.index + m[0].length;
    const win = src.slice(after, after + 2000);
    let close = win.search(/<\/a\s*>|<a\b/i);
    if (close < 0) { close = win.search(/<\/?(p|div|br|tr|td|li|table|h[1-6]|form)\b/i); if (close < 0) close = Math.min(win.length, 200); }
    const text = close > 0 ? collapse(decodeEntities(win.slice(0, close).replace(/<[^>]*>/g, " "))) : "";
    out.push({ raw: href, location, offset: m.index, display_text: text || null, title: attr(m[1], "title") });
    if (out.length >= MAX_URLS) break;
  }
  for (const m of src.matchAll(/<area\b([^>]*)>/gi)) { if (out.length >= MAX_URLS) break; const href = attr(m[1], "href"); if (href) out.push({ raw: href, location, offset: m.index, display_text: attr(m[1], "alt") }); }
  for (const m of src.matchAll(/<form\b([^>]*)>/gi)) {
    if (forms.length >= MAX_FORMS) break;
    const action = attr(m[1], "action");
    forms.push({ action: action || null, method: (attr(m[1], "method") || "get").toLowerCase(), offset: m.index, has_password_field: /<input\b[^>]*type\s*=\s*["']?password/i.test(src.slice(m.index, m.index + 20000)) });
    if (action) out.push({ raw: action, location: location + " (form action)", offset: m.index, display_text: null, form: true });
  }
  return { links: out, forms };
}

const IPV4_DOTTED = /^(?:\d{1,3}\.){3}\d{1,3}$/;
/** Detect a hostname that WHATWG URL normalizes into an IPv4 address from an unusual encoding. */
function obfuscatedIp(rawHost, normalizedHost) {
  if (!IPV4_DOTTED.test(normalizedHost)) return false;
  const original = rawHost.toLowerCase();
  return original !== normalizedHost && /^[0-9a-fx.]+$/.test(original);
}

function rawHostOf(raw) {
  const m = String(raw).match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)/i);
  return m ? m[1] : "";
}

const DISPLAY_DOMAIN = /(?:https?:\/\/)?((?:[a-z0-9\u00a1-\uffff](?:[a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?\.)+[a-z\u00a1-\uffff]{2,63})(?=$|[\/\s:?#),;!])/i;

/** Normalize and inspect a single URL. Returns a link record with observed indicators. */
export function inspectUrl(candidate) {
  const raw = String(candidate.raw || "").trim();
  const scheme = (raw.match(/^([a-z][a-z0-9+.-]*):/i)?.[1] || "").toLowerCase();
  const record = { url: raw, normalized: null, scheme: scheme || (raw.toLowerCase().startsWith("www.") ? "none" : null), host: null, host_unicode: null, registrable_domain: null, public_suffix: null, subdomain: null, port: null, path: null, is_ip: false, is_idn: false, embedded_urls: [], sources: [{ location: candidate.location, display_text: candidate.display_text || null, offset: candidate.offset }], findings: [] };
  const add = (rule, o) => record.findings.push(makeFinding(rule, { source: candidate.location, url: raw, ...o }));

  if (["javascript", "data", "vbscript"].includes(scheme)) {
    add("link.dangerous-scheme", { evidence: truncate(raw, 120), details: { scheme } });
    record.normalized = truncate(raw, 200);
    return record;
  }
  if (scheme && !["http", "https"].includes(scheme)) return null; // mailto:, tel:, cid:, etc. are not web destinations
  let parsed;
  try { parsed = new URL(scheme ? raw : "http://" + raw); } catch { return null; }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  const info = domainInfo(host);
  if (!info) return null;
  record.normalized = parsed.href;
  record.host = host;
  record.host_unicode = info.unicode;
  record.registrable_domain = info.registrable;
  record.public_suffix = info.public_suffix;
  record.subdomain = info.subdomain || null;
  record.port = parsed.port || null;
  record.path = parsed.pathname + (parsed.search ? "?\u2026" : "");
  record.is_ip = info.is_ip;
  record.is_idn = info.is_idn;
  const domainField = info.registrable || host;

  if (parsed.protocol === "http:" && scheme) add("link.http", { evidence: "Scheme is http:// for " + host, domain: domainField });
  if (parsed.username || parsed.password) add("link.userinfo", { evidence: `Text before "@" is "${truncate(decodeURIComponent(parsed.username), 60)}"; real host is ${host}`, domain: domainField });
  if (info.is_ip) {
    if (obfuscatedIp(rawHostOf(raw), host)) add("link.ip-obfuscated", { evidence: `Host "${rawHostOf(raw)}" decodes to IP ${host}`, domain: host });
    else add("link.ip-host", { evidence: "Destination host is IP address " + host, domain: host });
  }
  if (info.is_idn) add("link.idn", { evidence: `${host} displays as "${info.unicode}"`, domain: domainField });
  if (info.registrable && URL_SHORTENERS.has(info.registrable)) add("link.shortener", { evidence: info.registrable + " is a known URL-shortening service; final destination not resolved", domain: info.registrable });
  if (!info.is_ip && info.subdomain && info.subdomain.split(".").length >= 4) add("link.deep-subdomain", { evidence: `${info.subdomain.split(".").length} subdomain levels before ${info.registrable}`, domain: domainField });
  if (parsed.port && !["80", "443"].includes(parsed.port)) add("link.port", { evidence: "Explicit port :" + parsed.port, domain: domainField });

  const look = lookalike(host);
  if (look) {
    const rule = look.technique === "brand-in-subdomain" ? "link.brand-in-subdomain" : "link.lookalike";
    add(rule, { evidence: look.detail, domain: domainField, details: { brand: look.brand, technique: look.technique, legitimate_domains: look.legitimate_domains }, priority: look.technique === "same-name-different-suffix" ? "medium" : null, points: look.technique === "same-name-different-suffix" ? 10 : null });
  }

  for (const [k, v] of parsed.searchParams) {
    if (record.embedded_urls.length >= 3) break;
    let val = v; try { val = decodeURIComponent(v); } catch { /* keep raw */ }
    const inner = val.match(/^(?:https?:)?\/\/([^/?#\s]+)/i) || val.match(/^https?%3a%2f%2f([^/%?#\s]+)/i);
    if (!inner) continue;
    let innerHost = inner[1].toLowerCase().replace(/^[^@]*@/, "").replace(/:\d+$/, "");
    if (!innerHost || sameOrganization(innerHost, host)) continue;
    record.embedded_urls.push({ parameter: k, host: innerHost });
    add("link.redirect-param", { evidence: `Parameter "${truncate(k, 30)}" carries a link to ${innerHost}`, domain: domainField, details: { parameter: k, embedded_host: innerHost } });
  }

  if (candidate.display_text) {
    const shown = candidate.display_text.match(DISPLAY_DOMAIN);
    if (shown) {
      let shownHost = shown[1].toLowerCase();
      try { shownHost = new URL("http://" + shownHost).hostname; } catch { /* keep */ }
      const shownInfo = domainInfo(shownHost);
      if (shownInfo?.registrable && shownInfo.public_suffix && shownInfo.is_icann_suffix && !sameOrganization(shownHost, host)) {
        const brand = isBrandDomain(shownInfo.registrable);
        add("link.text-mismatch", { evidence: `Link text shows "${truncate(candidate.display_text, 80)}" (${shownInfo.registrable}) but the link goes to ${info.registrable || host}`, domain: domainField, details: { displayed_domain: shownInfo.registrable, actual_domain: info.registrable || host, displayed_brand: brand?.brand || null } });
      }
    }
  }
  return record;
}

/** Collect, de-duplicate and inspect URLs from all message parts. */
export function collectLinks(parts) {
  const candidates = [], forms = [];
  for (const p of parts) {
    if (!p.content) continue;
    if (p.kind === "html") {
      const h = extractHtmlLinks(p.content, p.location);
      candidates.push(...h.links);
      forms.push(...h.forms.map(f => ({ ...f, location: p.location })));
    } else {
      candidates.push(...extractTextUrls(p.content, p.location));
    }
  }
  const byUrl = new Map();
  for (const c of candidates.slice(0, MAX_URLS * 2)) {
    const rec = inspectUrl(c);
    if (!rec) continue;
    const existing = byUrl.get(rec.normalized);
    if (!existing) { if (byUrl.size >= MAX_URLS) break; byUrl.set(rec.normalized, rec); continue; }
    // Same destination seen again (e.g. text part and HTML part): merge sources and any new evidence.
    existing.sources.push(...rec.sources);
    for (const f of rec.findings) if (!existing.findings.some(x => x.rule === f.rule && x.evidence === f.evidence)) existing.findings.push(f);
  }
  return { links: [...byUrl.values()], forms };
}
