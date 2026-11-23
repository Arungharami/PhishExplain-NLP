// Domain structure helpers built on the Public Suffix List (via the vendored tldts library).
// Comparisons use registrable domains (eTLD+1), never naive substring tests, so
// "login.paypal.com" and "paypal.com" are the same organization while "paypal.com.evil.example" is not.
import { parse as tldParse } from "../../vendor/tldts.js";
import { hostnameToUnicode, scriptsIn, editDistance } from "./text.js";

export function domainInfo(host) {
  const hostname = String(host ?? "").trim().toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (!hostname) return null;
  const p = tldParse(hostname, { allowPrivateDomains: true, extractHostname: false });
  const ipv6 = hostname.includes(":");
  return {
    hostname,
    unicode: hostnameToUnicode(hostname),
    registrable: p.isIp || ipv6 ? null : (p.domain || null),
    public_suffix: p.publicSuffix || null,
    subdomain: p.subdomain || "",
    label: p.domainWithoutSuffix || null,
    is_ip: Boolean(p.isIp || ipv6),
    is_icann_suffix: p.isIcann === true,
    is_idn: /(^|\.)xn--/i.test(hostname)
  };
}

/** True when two hostnames share the same registrable domain (case-insensitive). */
export function sameOrganization(a, b) {
  const x = domainInfo(a), y = domainInfo(b);
  if (!x || !y) return false;
  if (x.is_ip || y.is_ip) return x.hostname === y.hostname;
  return Boolean(x.registrable && x.registrable === y.registrable);
}

// Organizations frequently impersonated in phishing. Used ONLY to describe resemblance;
// resemblance to a brand is a heuristic, not a determination that a domain is malicious.
export const PROTECTED_BRANDS = Object.freeze([
  { brand: "PayPal", domains: ["paypal.com", "paypal.me"], token: "paypal" },
  { brand: "Microsoft", domains: ["microsoft.com", "office.com", "office365.com", "microsoftonline.com", "live.com", "outlook.com", "sharepoint.com", "onedrive.com", "msn.com"], token: "microsoft" },
  { brand: "Microsoft Office", domains: ["office.com", "office365.com", "microsoft.com"], token: "office365" },
  { brand: "Outlook", domains: ["outlook.com", "live.com", "microsoft.com"], token: "outlook" },
  { brand: "Apple", domains: ["apple.com", "icloud.com"], token: "apple" },
  { brand: "iCloud", domains: ["icloud.com", "apple.com"], token: "icloud" },
  { brand: "Google", domains: ["google.com", "gmail.com", "youtube.com", "googleusercontent.com", "goo.gl"], token: "google" },
  { brand: "Gmail", domains: ["gmail.com", "google.com"], token: "gmail" },
  { brand: "Amazon", domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.ca", "amazonaws.com", "aws.amazon.com"], token: "amazon" },
  { brand: "Netflix", domains: ["netflix.com"], token: "netflix" },
  { brand: "Facebook", domains: ["facebook.com", "fb.com", "meta.com"], token: "facebook" },
  { brand: "Instagram", domains: ["instagram.com"], token: "instagram" },
  { brand: "WhatsApp", domains: ["whatsapp.com", "whatsapp.net"], token: "whatsapp" },
  { brand: "LinkedIn", domains: ["linkedin.com", "lnkd.in"], token: "linkedin" },
  { brand: "DHL", domains: ["dhl.com", "dhl.de"], token: "dhl" },
  { brand: "FedEx", domains: ["fedex.com"], token: "fedex" },
  { brand: "UPS", domains: ["ups.com"], token: "ups" },
  { brand: "USPS", domains: ["usps.com"], token: "usps" },
  { brand: "Chase", domains: ["chase.com", "jpmorganchase.com"], token: "chase" },
  { brand: "Wells Fargo", domains: ["wellsfargo.com"], token: "wellsfargo" },
  { brand: "Bank of America", domains: ["bankofamerica.com", "bofa.com"], token: "bankofamerica" },
  { brand: "Citi", domains: ["citi.com", "citibank.com"], token: "citibank" },
  { brand: "American Express", domains: ["americanexpress.com", "aexp.com"], token: "americanexpress" },
  { brand: "IRS", domains: ["irs.gov"], token: "irs" },
  { brand: "DocuSign", domains: ["docusign.com", "docusign.net"], token: "docusign" },
  { brand: "Dropbox", domains: ["dropbox.com"], token: "dropbox" },
  { brand: "Adobe", domains: ["adobe.com"], token: "adobe" },
  { brand: "Coinbase", domains: ["coinbase.com"], token: "coinbase" },
  { brand: "Binance", domains: ["binance.com"], token: "binance" },
  { brand: "eBay", domains: ["ebay.com"], token: "ebay" },
  { brand: "Walmart", domains: ["walmart.com"], token: "walmart" },
  { brand: "Spotify", domains: ["spotify.com"], token: "spotify" },
  { brand: "Zoom", domains: ["zoom.us", "zoom.com"], token: "zoom" },
  { brand: "Steam", domains: ["steampowered.com", "steamcommunity.com"], token: "steam" },
  { brand: "Okta", domains: ["okta.com", "okta-emea.com"], token: "okta" },
  { brand: "Salesforce", domains: ["salesforce.com", "force.com"], token: "salesforce" },
  { brand: "Twitter / X", domains: ["twitter.com", "x.com"], token: "twitter" }
]);

export const URL_SHORTENERS = new Set(["bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly", "bit.do", "qrco.de", "v.gd", "shorte.st", "adf.ly", "lnkd.in", "trib.al", "soo.gd", "tinyurl.at", "short.io", "bl.ink", "clck.ru", "u.to", "x.gd", "urlz.fr", "surl.li", "linktr.ee"]);

export const FREE_MAIL = new Set(["gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "tutanota.com", "fastmail.com", "qq.com", "163.com", "mail.ru"]);

// Visually confusable sequences → canonical skeleton (subset of Unicode TR39 + common ASCII tricks).
const CONFUSABLE_MULTI = [["rn", "m"], ["vv", "w"], ["cl", "d"], ["nn", "m"]];
const CONFUSABLE_CHAR = { "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", i: "l", "|": "l", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ɡ": "g", "ı": "l", "à": "a", "á": "a", "â": "a", "ä": "a", "è": "e", "é": "e", "ê": "e", "ì": "l", "í": "l", "ï": "l", "ò": "o", "ó": "o", "ö": "o", "ú": "u", "ü": "u", "ç": "c", "ñ": "n" };
export function skeleton(label) {
  let s = String(label).toLowerCase().normalize("NFKC");
  s = [...s].map(ch => CONFUSABLE_CHAR[ch] ?? ch).join("");
  for (const [a, b] of CONFUSABLE_MULTI) s = s.split(a).join(b);
  return s.replace(/[-_.]/g, "");
}

const brandOwnsRegistrable = (b, registrable) => b.domains.some(d => registrable === d || registrable.endsWith("." + d));
export function isBrandDomain(registrable) {
  if (!registrable) return null;
  return PROTECTED_BRANDS.find(b => brandOwnsRegistrable(b, registrable)) || null;
}

/**
 * Describe resemblance between a hostname and a protected brand.
 * Returns null or { brand, legitimate_domains, technique, detail }.
 * Techniques: "confusable-characters", "edit-distance", "brand-plus-words", "brand-in-subdomain", "mixed-script".
 */
export function lookalike(host) {
  const info = domainInfo(host);
  if (!info || info.is_ip || !info.registrable) return null;
  if (isBrandDomain(info.registrable)) return null;
  const labelUnicode = hostnameToUnicode(info.label || "");
  const labelSkel = skeleton(labelUnicode);
  const labelAscii = (info.label || "").toLowerCase();
  const tokens = labelUnicode.toLowerCase().split(/[-_]+/).filter(Boolean);
  for (const b of PROTECTED_BRANDS) {
    const legit = b.domains;
    const brandLabels = [...new Set(legit.map(d => domainInfo(d)?.label).filter(Boolean))];
    for (const bl of brandLabels) {
      if (bl.length < 4) continue;
      if (labelUnicode.toLowerCase() === bl) {
        // Same label on a different public suffix, e.g. paypal.co.example — could be a regional site.
        return { brand: b.brand, legitimate_domains: legit, technique: "same-name-different-suffix", detail: `Uses the name "${bl}" with a different domain suffix (${info.public_suffix}).` };
      }
      if (labelSkel === skeleton(bl) && labelAscii !== bl) {
        return { brand: b.brand, legitimate_domains: legit, technique: info.is_idn ? "confusable-unicode" : "confusable-characters", detail: `"${labelUnicode}" visually resembles "${bl}" after normalizing confusable characters.` };
      }
      // Edit distance is only used for longer brand names; short names collide with ordinary words.
      const maxD = bl.length >= 9 ? 2 : 1;
      const d = bl.length >= 6 ? editDistance(labelSkel, skeleton(bl), maxD) : Infinity;
      if (d >= 1 && d <= maxD) {
        return { brand: b.brand, legitimate_domains: legit, technique: "edit-distance", detail: `"${labelUnicode}" is ${d} character edit(s) away from "${bl}".` };
      }
    }
    if (b.token.length >= 5 && tokens.length > 1 && tokens.some(t => t === b.token || skeleton(t) === skeleton(b.token))) {
      return { brand: b.brand, legitimate_domains: legit, technique: "brand-plus-words", detail: `The registered domain combines "${b.token}" with other words (${info.registrable}).` };
    }
    if (b.token.length >= 6 && labelSkel.includes(skeleton(b.token)) && labelSkel !== skeleton(b.token)) {
      return { brand: b.brand, legitimate_domains: legit, technique: "brand-plus-words", detail: `The registered domain embeds "${b.token}" inside a longer name (${info.registrable}).` };
    }
    if (b.token.length >= 4 && info.subdomain) {
      const subLabels = info.subdomain.toLowerCase().split(".");
      if (subLabels.includes(b.token) || legit.some(d => (info.subdomain + ".").toLowerCase().includes(d + "."))) {
        return { brand: b.brand, legitimate_domains: legit, technique: "brand-in-subdomain", detail: `"${b.token}" appears in the subdomain, but the registered domain is ${info.registrable}.` };
      }
    }
  }
  const scripts = scriptsIn(labelUnicode);
  if (info.is_idn && scripts.length > 1) return { brand: null, legitimate_domains: [], technique: "mixed-script", detail: `Hostname mixes ${scripts.join(" and ")} characters, a common homograph technique.` };
  return null;
}
