// Sender identity checks based on parsed From / Reply-To / Return-Path / Sender.
import { domainInfo, sameOrganization, lookalike, FREE_MAIL, PROTECTED_BRANDS, isBrandDomain } from "./domains.js";
import { makeFinding } from "./rules.js";
import { truncate } from "./text.js";

const ORG_WORDS = /\b(support|security|service|services|team|department|dept|billing|accounts?|payroll|admin(istrator)?|help ?desk|it|hr|human resources|finance|bank|customer care|verification|compliance|notifications?|no-?reply|office)\b/i;
const EMAIL_IN_TEXT = /[a-z0-9._%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i;

export function addressDomain(address) {
  const at = String(address || "").lastIndexOf("@");
  return at > 0 ? String(address).slice(at + 1).toLowerCase().replace(/[>\s]+$/, "") : null;
}

export function analyzeSender(model) {
  const findings = [];
  const from = model.from;
  const fromDomain = addressDomain(from?.address);
  const fromInfo = fromDomain ? domainInfo(fromDomain) : null;
  const replyTo = model.reply_to || [];
  const rpDomain = addressDomain(model.return_path);

  const summary = {
    display_name: from?.name || null,
    address: from?.address || null,
    domain: fromDomain,
    domain_unicode: fromInfo?.unicode || null,
    registrable_domain: fromInfo?.registrable || null,
    reply_to: replyTo.map(r => ({ ...r, registrable_domain: domainInfo(addressDomain(r.address))?.registrable || null })),
    return_path: model.return_path || null,
    return_path_registrable: rpDomain ? domainInfo(rpDomain)?.registrable || null : null,
    sender_header: model.sender?.address || null,
    is_free_mail: fromInfo?.registrable ? FREE_MAIL.has(fromInfo.registrable) : false,
    brand_domain: fromInfo?.registrable ? (isBrandDomain(fromInfo.registrable)?.brand || null) : null
  };

  const headersSupplied = (model.headers || []).length > 0;
  if (headersSupplied && !from?.address) {
    if ((model.from_raw || []).length) findings.push(makeFinding("sender.multiple-from", { evidence: "From header could not be parsed: " + truncate(model.from_raw[0], 100), source: "header:From" }));
    else findings.push(makeFinding("sender.missing-from", { evidence: "No From header in the supplied headers", source: "header:From" }));
    return { summary, findings };
  }
  if (!from?.address) return { summary, findings };

  if ((model.from_raw || []).length > 1 || /,\s*[^,]*@/.test(String(model.from_raw?.[0] || "").replace(/"[^"]*"/g, ""))) findings.push(makeFinding("sender.multiple-from", { evidence: "From: " + truncate((model.from_raw || []).join(" | "), 140), source: "header:From" }));

  for (const r of replyTo) {
    const rd = addressDomain(r.address);
    if (rd && fromDomain && !sameOrganization(rd, fromDomain)) {
      findings.push(makeFinding("sender.replyto-mismatch", { evidence: `From ${fromInfo?.registrable || fromDomain} → Reply-To ${domainInfo(rd)?.registrable || rd} (${r.address})`, source: "header:Reply-To", domain: domainInfo(rd)?.registrable || rd, priority: FREE_MAIL.has(domainInfo(rd)?.registrable) ? "high" : null, points: FREE_MAIL.has(domainInfo(rd)?.registrable) ? 20 : null }));
      break;
    }
  }
  if (rpDomain && fromDomain && !sameOrganization(rpDomain, fromDomain)) findings.push(makeFinding("sender.returnpath-mismatch", { evidence: `From ${fromInfo?.registrable || fromDomain} vs Return-Path ${domainInfo(rpDomain)?.registrable || rpDomain}`, source: "header:Return-Path", domain: domainInfo(rpDomain)?.registrable || rpDomain }));

  const name = from.name || "";
  const nameEmail = name.match(EMAIL_IN_TEXT);
  if (nameEmail && !sameOrganization(nameEmail[1], fromDomain)) findings.push(makeFinding("sender.display-address", { evidence: `Display name "${truncate(name, 80)}" shows ${nameEmail[0]}; actual address is ${from.address}`, source: "header:From", domain: fromInfo?.registrable || fromDomain }));

  if (name && !nameEmail) {
    const lowered = name.toLowerCase().replace(/[^a-z0-9 ]/g, " ");
    const brand = PROTECTED_BRANDS.find(b => new RegExp("\\b" + b.brand.toLowerCase().replace(/[^a-z0-9 ]/g, " ").replace(/\s+/g, "\\s*") + "\\b").test(lowered) || (b.token.length >= 5 && lowered.replace(/\s+/g, "").includes(b.token)));
    if (brand && !brand.domains.some(d => sameOrganization(d, fromDomain))) findings.push(makeFinding("sender.display-brand", { evidence: `Display name "${truncate(name, 80)}" invokes ${brand.brand}; sending domain is ${fromInfo?.registrable || fromDomain}`, source: "header:From", domain: fromInfo?.registrable || fromDomain, details: { brand: brand.brand, legitimate_domains: brand.domains } }));
    else if (summary.is_free_mail && ORG_WORDS.test(name)) findings.push(makeFinding("sender.freemail-org", { evidence: `Display name "${truncate(name, 80)}" sent from free webmail ${fromInfo.registrable}`, source: "header:From", domain: fromInfo.registrable }));
  }

  const look = lookalike(fromDomain);
  if (look) findings.push(makeFinding("sender.lookalike", { evidence: look.detail, source: "header:From", domain: fromInfo?.registrable || fromDomain, details: { brand: look.brand, technique: look.technique, legitimate_domains: look.legitimate_domains } }));
  if (fromInfo?.is_idn) findings.push(makeFinding("sender.idn", { evidence: `${fromDomain} displays as "${fromInfo.unicode}"`, source: "header:From", domain: fromDomain }));

  const local = from.address.split("@")[0] || "";
  const digits = (local.match(/\d/g) || []).length;
  if (local.length > 40 || (local.length >= 10 && digits / local.length > 0.5) || /[a-z0-9]{24,}/i.test(local) && !/[aeiou]{1}.*[aeiou]/i.test(local.slice(0, 12))) findings.push(makeFinding("sender.unusual-address", { evidence: "Local part: " + truncate(local, 60), source: "header:From", domain: fromInfo?.registrable || fromDomain }));

  return { summary, findings };
}
