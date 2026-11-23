// Plain-language safer next steps, derived from the specific evidence observed.
export function recommendations(findings, attention) {
  const has = prefix => findings.some(f => f.rule.startsWith(prefix) && f.points > 0);
  const recs = [];
  const add = (id, title, detail) => { if (!recs.some(r => r.id === id)) recs.push({ id, title, detail }); };
  if (has("link.") || has("html.form")) add("links", "Don't click the links", "Open the organization's website or app yourself by typing an address you already know, or use a saved bookmark.");
  if (has("lang.credential") || has("combo.link-credential")) add("credentials", "Never send passwords from an email request", "Legitimate services do not ask you to provide or confirm your password by email or through an emailed link.");
  if (has("lang.otp")) add("otp", "Never share one-time codes", "A verification code lets someone complete a login or payment as you. No real support team needs you to read or forward it.");
  if (has("lang.payment")) add("payment", "Verify payment or bank-detail changes by phone", "Call the requester using a phone number from a previous invoice, contract or official website — never from this email. This is the main defense against business email compromise.");
  if (has("attach.")) add("attachments", "Don't open the attachment", "If you were expecting a file, confirm with the sender through a separate, known channel first. Never enable macros or 'editing' on unexpected documents.");
  if (has("sender.") || has("header.")) add("sender", "Don't trust the sender name alone", "Display names and From addresses are easy to forge. Contact the person or organization through details you already have.");
  if (has("lang.account-threat") || has("lang.urgency")) add("pressure", "Take your time", "Pressure and threats are designed to rush you. Check your account status directly in the official app or website.");
  if (attention.index >= 25) add("report", "Report the message", "Use your email provider's \"Report phishing\" option or forward it to your organization's security team, then delete it.");
  if (has("lang.credential") || has("lang.otp")) add("mfa", "If you already responded, secure the account", "Change the password from the official site, sign out other sessions, and turn on multi-factor authentication. Contact your bank immediately if you shared financial details.");
  add("independent", "A low result is not a guarantee", "Shield only checks for specific indicators. When a request is unexpected, verify it independently before acting.");
  return recs;
}

export const EDUCATION = Object.freeze([
  { term: "Phishing", text: "Messages that impersonate a trusted party to trick you into revealing information, paying money, or installing malware." },
  { term: "Spear phishing", text: "Phishing tailored to a specific person or team, often using names, projects or details gathered from public sources." },
  { term: "Business email compromise (BEC)", text: "Fraud in which an attacker impersonates an executive, colleague or supplier to redirect payments or obtain sensitive data, often without any link or attachment." },
  { term: "Credential theft", text: "Collecting usernames, passwords and one-time codes, usually through a fake sign-in page reached from an email link." },
  { term: "URL redirection", text: "A link that passes through one or more intermediate addresses (such as shorteners or open redirects) so the final destination is hidden." },
  { term: "Domain impersonation", text: "Registering domains that look like a real organization's — swapped letters, extra words, different suffixes or look-alike Unicode characters." },
  { term: "SPF", text: "Sender Policy Framework: lets a domain list the servers allowed to send its mail. Checked by the receiving server against the envelope sender." },
  { term: "DKIM", text: "DomainKeys Identified Mail: a cryptographic signature that lets a receiving server confirm a message was authorized by the signing domain and not altered." },
  { term: "DMARC", text: "Domain-based Message Authentication, Reporting and Conformance: tells receivers how to handle mail whose visible From domain is not aligned with a passing SPF or DKIM result." }
]);
