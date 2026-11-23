// Header analysis: Received chain and authentication *claims*.
// TRUST BOUNDARY: Shield never performs SPF/DKIM/DMARC verification. Authentication-Results and
// Received-SPF headers in user-supplied text are recorded as UNVERIFIED CLAIMS: anyone can type or
// edit them, and only the receiving mail server that added them (and only for its own authserv-id)
// is in a position to vouch for them.
import { domainInfo, sameOrganization } from "./domains.js";
import { makeFinding } from "./rules.js";
import { collapse, truncate } from "./text.js";

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/;
const IPV6 = /\b(?:IPv6:)?((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}|::1)\b/i;

export function isPrivateIp(ip) {
  if (!ip) return false;
  if (ip.includes(":")) return /^(::1$|fc|fd|fe80)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 0;
}

/** Parse one Received header value into its clauses. */
export function parseReceived(value) {
  const v = collapse(value);
  const semi = v.lastIndexOf(";");
  const dateText = semi >= 0 ? v.slice(semi + 1).trim() : null;
  const body = semi >= 0 ? v.slice(0, semi) : v;
  const clause = name => { const m = body.match(new RegExp("(?:^|\\s)" + name + "\\s+([^\\s;]+)(?:\\s+(\\([^)]*\\)))?", "i")); return m ? { value: m[1], comment: m[2] || null } : null; };
  const from = clause("from"), by = clause("by"), withP = clause("with"), id = clause("id"), forC = clause("for");
  const fromSegment = body.match(/from\s+([\s\S]*?)(?=\sby\s|$)/i)?.[1] || "";
  // Prefer the IP the receiving server recorded in its comment over the sender-chosen HELO name.
  const comment = fromSegment.match(/\(([^)]*)\)/)?.[1] || "";
  const ip = comment.match(IPV4)?.[0] || comment.match(IPV6)?.[1] || fromSegment.match(IPV4)?.[0] || fromSegment.match(IPV6)?.[1] || null;
  const heloIp = from?.value?.match(IPV4)?.[0] || null;
  const parsedDate = dateText ? new Date(dateText.replace(/\s*\([^)]*\)\s*$/, "")) : null;
  return {
    raw: truncate(v, 600),
    from_host: from?.value || null,
    from_comment: from?.comment || null,
    from_ip: ip,
    from_ip_private: ip ? isPrivateIp(ip) : null,
    helo_ip: heloIp && heloIp !== ip ? heloIp : null,
    by_host: by?.value || null,
    protocol: withP?.value || null,
    id: id?.value || null,
    for: forC?.value?.replace(/[<>]/g, "") || null,
    date_text: dateText,
    timestamp: parsedDate && !Number.isNaN(parsedDate.getTime()) ? parsedDate.toISOString() : null
  };
}

/** Parse an Authentication-Results (RFC 8601) value into authserv-id and method results. */
export function parseAuthResults(value) {
  const v = collapse(value).replace(/\([^)]*\)/g, " ");
  const parts = v.split(";").map(s => s.trim()).filter(Boolean);
  const authserv = (parts[0] || "").split(/\s+/)[0] || null;
  const results = [];
  for (const p of parts.slice(1)) {
    const m = p.match(/^([a-z][a-z0-9-]*)\s*=\s*([a-z]+)/i);
    if (!m) continue;
    const props = {};
    for (const pm of p.matchAll(/\b((?:header|smtp|policy|body)\.[a-z-]+)\s*=\s*("[^"]*"|[^\s;]+)/gi)) props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, "");
    results.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), properties: props });
  }
  return { authserv_id: authserv, results };
}

export function parseReceivedSpf(value) {
  const v = collapse(value);
  const m = v.match(/^([a-z]+)/i);
  const env = v.match(/envelope-from=("?)([^";\s]+)\1/i);
  return { result: m ? m[1].toLowerCase() : null, envelope_from: env ? env[2].toLowerCase() : null, raw: truncate(v, 300) };
}

export function parseDkimSignature(value) {
  const tags = {};
  for (const m of collapse(value).matchAll(/(?:^|;)\s*([a-z]+)\s*=\s*([^;]*)/gi)) tags[m[1].toLowerCase()] = m[2].trim();
  return { domain: tags.d?.toLowerCase() || null, selector: tags.s || null, algorithm: tags.a || null, signed_headers: tags.h ? tags.h.split(":").map(s => s.trim().toLowerCase()).slice(0, 30) : [] };
}

/**
 * Analyze the header block of a parsed message.
 * @returns {{ received: object[], authentication: object, findings: object[] }}
 */
export function analyzeHeaders(model, fromDomain) {
  const findings = [];
  const headers = model.headers || [];
  // Received headers are prepended by each relay, so the first header is the most recent hop.
  const receivedNewestFirst = headers.filter(h => h.key === "received").map(h => parseReceived(h.value));
  const hops = receivedNewestFirst.slice().reverse().map((h, i) => ({ hop: i + 1, ...h }));
  let prev = null;
  for (const hop of hops) {
    if (hop.timestamp && prev?.timestamp) {
      const delta = (Date.parse(hop.timestamp) - Date.parse(prev.timestamp)) / 1000;
      hop.delay_seconds = Math.round(delta);
      if (delta < -300 && !findings.some(f => f.rule === "header.time-order")) findings.push(makeFinding("header.time-order", { evidence: `Hop ${hop.hop} is timestamped ${Math.round(-delta / 60)} min before hop ${prev.hop}`, source: "header:Received" }));
    } else hop.delay_seconds = null;
    if (hop.timestamp) prev = hop;
  }

  const ar = headers.filter(h => h.key === "authentication-results").map(h => parseAuthResults(h.value));
  const arc = headers.filter(h => h.key === "arc-authentication-results").map(h => parseAuthResults(h.value.replace(/^\s*i\s*=\s*\d+\s*;/i, "")));
  const spfHeaders = headers.filter(h => h.key === "received-spf").map(h => parseReceivedSpf(h.value));
  const dkimSigs = headers.filter(h => h.key === "dkim-signature").map(h => parseDkimSignature(h.value));

  // Summarize claims from the top-most Authentication-Results (closest to the final recipient).
  const top = ar[0] || null;
  const pick = method => top?.results.find(r => r.method === method) || null;
  const claim = (method, r) => r ? { method, result: r.result, domain: r.properties["header.d"] || r.properties["header.from"] || r.properties["smtp.mailfrom"]?.split("@").pop() || null, properties: r.properties, claimed_by: top.authserv_id, status: "unverified_claim" } : { method, result: null, status: "not_present" };
  const spf = pick("spf") ? claim("spf", pick("spf")) : (spfHeaders[0] ? { method: "spf", result: spfHeaders[0].result, domain: spfHeaders[0].envelope_from?.split("@").pop() || null, claimed_by: "Received-SPF header", status: "unverified_claim" } : { method: "spf", result: null, status: "not_present" });
  const dkim = claim("dkim", pick("dkim"));
  const dmarc = claim("dmarc", pick("dmarc"));

  const authentication = {
    verified: false,
    trust: ar.length || spfHeaders.length ? "unverified_pasted_header_claims" : "no_claims_present",
    explanation: "SPF, DKIM and DMARC were NOT verified by PhishExplain Shield. Values shown are claims copied from the supplied headers. They can be forged or edited, and are only meaningful when added by your own receiving mail server.",
    spf, dkim, dmarc,
    authentication_results_headers: ar.length,
    all_claims: ar,
    arc_claims: arc,
    received_spf: spfHeaders,
    dkim_signatures: dkimSigs
  };

  const failed = [spf, dkim, dmarc].filter(c => c.result && ["fail", "softfail", "permerror"].includes(c.result));
  if (failed.length) findings.push(makeFinding("header.auth-fail-claim", { evidence: failed.map(c => `${c.method.toUpperCase()}=${c.result}`).join(", ") + (top?.authserv_id ? ` (claimed by ${top.authserv_id})` : ""), source: "header:Authentication-Results" }));
  if (fromDomain && dmarc.result && dmarc.domain && !sameOrganization(dmarc.domain, fromDomain)) findings.push(makeFinding("header.dmarc-domain-mismatch", { evidence: `DMARC claim evaluates ${dmarc.domain}; visible From domain is ${fromDomain}`, source: "header:Authentication-Results", domain: dmarc.domain }));
  else if (fromDomain && dkim.result === "pass" && dkim.domain && !sameOrganization(dkim.domain, fromDomain)) findings.push(makeFinding("header.dmarc-domain-mismatch", { evidence: `DKIM claim passes for ${dkim.domain}, not the From domain ${fromDomain} (not aligned)`, source: "header:Authentication-Results", domain: dkim.domain }));

  const alignment = {
    from_domain: fromDomain || null,
    return_path_domain: model.return_path ? domainInfo(model.return_path.split("@").pop())?.registrable || null : null,
    dkim_signature_domains: [...new Set(dkimSigs.map(s => s.domain).filter(Boolean))],
    message_id_domain: model.message_id ? (domainInfo(String(model.message_id).replace(/[<>]/g, "").split("@").pop())?.registrable || null) : null
  };
  return { received: hops, authentication, alignment, findings };
}
