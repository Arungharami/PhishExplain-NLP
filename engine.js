/**
 * PhishExplain-NLP — transparent lexical signal extractor.
 * Research prototype; matching a cue is not a phishing diagnosis.
 * Every match is a substring of the original input with exact [start, end) offsets.
 */
export const SAMPLES = Object.freeze({
  account: {
    label: "Account alert",
    type: "synthetic illustration",
    text: "Subject: Account verification required\nFrom: Account Review <alerts@portal.example>\n\nHello,\nImmediate action required. Your account access will be paused in 24 hours unless you complete verification.\nPlease enter your password at https://verify.example/login to keep your access active.\n\nAccount Team"
  },
  delivery: {
    label: "Delivery update",
    type: "synthetic illustration",
    text: "Subject: Final delivery notice\nFrom: Package Service <update@ship.example>\n\nFinal notice: act now to avoid a return. Complete your delivery details within 12 hours at https://delivery.example/update. We will send another message after the address is confirmed."
  },
  normal: {
    label: "Routine message",
    type: "synthetic illustration",
    text: "Subject: Weekly research meeting\nFrom: Lab Coordinator <lab@university.example>\n\nHello team,\nThe research meeting is scheduled for Thursday at 2 PM. We will review the annotation guidelines and discuss disagreements in the dataset. The shared notes are in our course workspace.\n\nThank you."
  },
  ambiguous: {
    label: "Hard negative",
    type: "synthetic illustration",
    text: "Subject: Account security awareness\nFrom: Training Office <training@university.example>\n\nDuring security awareness training, we remind everyone: do not share your password or enter your password on unfamiliar pages. If a message says act now, verify its source through an official channel. Please read the guidelines; this is not an account verification request."
  }
});

const CATEGORIES = Object.freeze([
  { key: "url", title: "Link cues", explanation: "Visible web links; a URL alone does not imply a malicious destination." },
  { key: "urgency", title: "Urgency & pressure", explanation: "Language suggesting a deadline, demand, or consequence." },
  { key: "credential", title: "Credential requests", explanation: "Surface-form requests for sensitive sign-in information." }
]);

const LEXICONS = {
  urgency: [
    { id: "pressure-immediate", re: /\b(?:immediate(?:ly)?|urgent(?:ly)?)\b/gi },
    { id: "pressure-act-now", re: /\b(?:act now|action required|final notice|last warning|time[- ]sensitive)\b/gi },
    { id: "pressure-deadline", re: /\bwithin\s+\d+\s+(?:minutes?|hours?|days?)\b/gi },
    { id: "pressure-consequence", re: /\b(?:will be (?:suspended|locked|paused)|account access will be paused|expires? (?:today|soon)|before midnight)\b/gi }
  ],
  credential: [
    { id: "request-credential", re: /\b(?:enter|provide|confirm|send|share|submit|reset)\s+(?:your\s+|the\s+|an?\s+)?(?:account\s+)?(?:password|passcode|one[- ]time code|otp|verification code|security code|login credentials|sign[- ]in details)\b/gi },
    { id: "verify-credential", re: /\bverify\s+(?:your\s+|the\s+)?(?:password|login credentials|verification code|security code)\b/gi }
  ]
};
const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'\u201c\u201d]+/gi;
const ALLOWED_MAX = 20000;

function makeMatch(key, text, start, rule) {
  return { category: key, text, start, end: start + text.length, rule };
}

function uniqueMatches(hits) {
  const seen = new Set();
  return hits.filter(hit => {
    const key = hit.category + ":" + hit.start + ":" + hit.end;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a,b) => a.start - b.start || b.end - a.end);
}

export function extractSignals(input) {
  if (typeof input !== "string") throw new TypeError("Expected email text as a string");
  if (input.length > ALLOWED_MAX) throw new RangeError("Input exceeds the 20,000 character prototype limit");
  const hits = [];
  const urlPattern = new RegExp(URL_PATTERN.source, URL_PATTERN.flags);
  for (const match of input.matchAll(urlPattern)) {
    const cleaned = match[0].replace(/[),.;!?]+$/g, "");
    if (cleaned.length > 0) hits.push(makeMatch("url", cleaned, match.index, "http-url-pattern"));
  }
  for (const [category, rules] of Object.entries(LEXICONS)) {
    for (const {id, re} of rules) {
      const pattern = new RegExp(re.source, re.flags);
      for (const match of input.matchAll(pattern)) hits.push(makeMatch(category, match[0], match.index, id));
    }
  }
  const matches = uniqueMatches(hits);
  const groups = CATEGORIES.map(c => ({
    ...c,
    matches: matches.filter(x => x.category === c.key)
  }));
  return {
    version: "baseline-0.1",
    task: "linguistic_cue_extraction",
    engine: "local_rules_regex",
    model_status: "baseline_only_transformer_pending",
    input_length: input.length,
    total_matches: matches.length,
    counts: Object.fromEntries(groups.map(g => [g.key, g.matches.length])),
    categories: groups,
    caveat: "These are lexical cues, not a phishing verdict; context and negation may cause false positives."
  };
}

export const ENGINE_MAX_LENGTH = ALLOWED_MAX;
