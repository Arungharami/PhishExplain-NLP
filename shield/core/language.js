// Social-engineering language cues ("shield-lang-1").
// Derived from the CAP 6640 research baseline (engine.js, which stays frozen for the study) and extended
// for product use. Every match keeps exact [start,end) offsets into the analyzed text.
// Context safeguards mark matches that are negated, quoted, or in awareness/training text and
// remove their weight from the attention index, because these are the dominant false positives.
import { makeFinding } from "./rules.js";
import { excerpt } from "./text.js";

export const LANGUAGE_RULESET = "shield-lang-1";
const CODE = "(?:one[- ]time (?:pass)?(?:code|password|pin)|otp|verification code|security code|authentication code|2fa code|login code|sign[- ]in code|confirmation code|six[- ]digit code|6[- ]digit code|passcode|pin(?: code| number)?)";
const CRED = "(?:password|passcode|login credentials|log[- ]?in details|sign[- ]in details|credentials|username and password|banking (?:login|password)|account (?:password|credentials))";

export const LANGUAGE_RULES = Object.freeze({
  urgency: [
    /\b(?:immediate(?:ly)?|urgent(?:ly)?|asap|right away|without delay)\b/gi,
    /\b(?:act now|action required|immediate action|final (?:notice|warning|reminder)|last (?:warning|chance|notice)|time[- ]sensitive|respond (?:now|today|immediately)|don'?t delay)\b/gi,
    /\bwithin (?:the next )?\d+\s*(?:minutes?|mins?|hours?|hrs?|days?)\b/gi,
    /\b(?:expires? (?:today|tonight|soon|in \d+)|before (?:midnight|end of (?:the )?day|close of business)|by end of day|today only|deadline (?:is )?today)\b/gi
  ],
  "account-threat": [
    /\b(?:will|may|could) be (?:permanently )?(?:suspended|locked|closed|deactivated|terminated|disabled|deleted|restricted|blocked|paused|frozen)\b/gi,
    /\b(?:account|access|mailbox|profile|card)(?: access)? (?:has been|was|is|will be) (?:temporarily )?(?:suspended|locked|limited|restricted|compromised|disabled|blocked|frozen|on hold|paused)\b/gi,
    /\b(?:unusual|suspicious|unauthori[sz]ed|unrecogni[sz]ed) (?:sign[- ]?in|log[- ]?in|activity|access|transaction|charge|payment)s?\b/gi,
    /\b(?:mailbox|storage) (?:is )?(?:full|almost full|over (?:its )?quota)\b/gi
  ],
  credential: [
    new RegExp("\\b(?:enter|provide|confirm|send|share|submit|update|verify|re-?enter|type|reply with|validate)\\s+(?:us\\s+)?(?:your\\s+|the\\s+|an?\\s+)?(?:current\\s+|account\\s+|email\\s+)?" + CRED + "\\b", "gi"),
    /\b(?:verify|confirm|validate|update) (?:your )?(?:identity|account (?:details|information|info)|billing (?:details|information)|payment (?:details|information|method))\b/gi,
    /(?<![/\w.-])(?:log ?in|sign ?in|click (?:here|below|the link)) (?:to|and) (?:verify|confirm|validate|restore|unlock|reactivate|update)\b/gi,
    /\b(?:social security number|ssn|credit card (?:number|details)|card (?:number|details) and cvv|cvv|bank (?:login|account number) and (?:password|pin))\b/gi
  ],
  otp: [
    new RegExp("\\b(?:send|share|provide|give|read|forward|reply with|tell|text)\\s+(?:me|us|it|back)?\\s*(?:the|your|that|this)?\\s*" + CODE + "\\b", "gi"),
    new RegExp("\\b" + CODE + "\\s+(?:that\\s+)?(?:we|i|you)\\s+(?:just\\s+)?(?:sent|received|texted|got)\\b", "gi")
  ],
  payment: [
    /\b(?:wire transfer|bank transfer|wire the (?:funds|payment|money)|ach transfer)\b/gi,
    /\b(?:gift ?cards?|itunes cards?|google play cards?|steam cards?|amazon cards?)\b/gi,
    /\b(?:new|updated|changed?) (?:bank(?:ing)?|payment|remittance|account) (?:details|information|instructions)\b/gi,
    /\b(?:overdue|outstanding|unpaid|past[- ]due) (?:invoice|payment|balance|bill)s?\b/gi,
    /\bpayment (?:has )?(?:failed|was declined|is pending|declined|required|overdue)\b/gi,
    /\b(?:bitcoin|btc|crypto(?:currency)? wallet|usdt)\b/gi
  ],
  impersonation: [
    /\b(?:this is|from|on behalf of) (?:the |your )?(?:it|i\.t\.|help ?desk|tech(?:nical)? support|security|payroll|hr|human resources|accounts payable|finance|admin(?:istrator)?) (?:department|team|desk|office)\b/gi,
    /\b(?:ceo|cfo|president|managing director|director|boss) (?:asked|needs|requests|wants|has asked)\b/gi,
    /\b(?:keep (?:this|it) (?:confidential|between us|private)|don'?t (?:tell|mention this to) anyone|i'?m (?:in a meeting|unavailable|traveling) (?:and|so)|can'?t talk (?:right )?now)\b/gi
  ]
});

const RULE_FOR = { urgency: "lang.urgency", "account-threat": "lang.account-threat", credential: "lang.credential", otp: "lang.otp", payment: "lang.payment", impersonation: "lang.impersonation" };
const NEGATION = /\b(?:do not|don'?t|never|will never|would never|won'?t|we will not|we don'?t|should never|no one should|not (?:ask|request|need)|avoid|refuse to|beware of|watch out for)\b/i;
const AWARENESS = /\b(?:phishing|scam(?:mer)?s?|fraud(?:ster)?s?|security awareness|training|for example|e\.g\.|such as|warning signs?|red flags?|attackers?|criminals?|this is not a)\b/i;

function sentenceBounds(text, start, end) {
  let a = start; while (a > 0 && !/[.!?\n]/.test(text[a - 1]) && start - a < 240) a--;
  let b = end; while (b < text.length && !/[.!?\n]/.test(text[b]) && b - end < 240) b++;
  return [a, b];
}

/** Classify the context of one match. Returns flags such as negated, quoted_reply, quotation, awareness_context. */
export function contextFlags(text, start, end) {
  const flags = [];
  const [a, b] = sentenceBounds(text, start, end);
  const before = text.slice(a, start), sentence = text.slice(a, b);
  if (NEGATION.test(before.slice(-90))) flags.push("negated");
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  if (/^\s*>/.test(text.slice(lineStart, start + 1))) flags.push("quoted_reply");
  // Inside a quotation on the same line: an odd number of straight quotes, or an unclosed curly quote.
  const lineBefore = text.slice(lineStart, start);
  const straight = (lineBefore.match(/"/g) || []).length;
  if (straight % 2 === 1 || lineBefore.lastIndexOf("“") > lineBefore.lastIndexOf("”")) flags.push("quotation");
  if (AWARENESS.test(sentence)) flags.push("awareness_context");
  return flags;
}

/**
 * Find language cues in one or more text segments.
 * @param {{text: string, location: string}[]} segments
 */
export function analyzeLanguage(segments, maxChars = 200000) {
  const spans = [];
  for (const seg of segments) {
    if (!seg.text) continue;
    const text = seg.text.slice(0, maxChars);
    for (const [cat, patterns] of Object.entries(LANGUAGE_RULES)) {
      for (const [i, re] of patterns.entries()) {
        for (const m of text.matchAll(new RegExp(re.source, re.flags))) {
          if (!m[0].trim()) continue;
          const start = m.index, end = start + m[0].length;
          spans.push({ category: cat, rule: `${cat}.${i + 1}`, text: m[0], start, end, location: seg.location, context_flags: contextFlags(text, start, end), excerpt: excerpt(text, start, end) });
        }
      }
    }
  }
  // De-duplicate overlapping spans of the same category within a location (keep the longest).
  // Longest span wins; ties go to the earlier span. Then restore reading order.
  spans.sort((x, y) => (y.end - y.start) - (x.end - x.start) || x.start - y.start);
  const kept = [];
  for (const s of spans) {
    if (kept.some(k => k.location === s.location && k.category === s.category && s.start < k.end && k.start < s.end)) continue;
    kept.push(s);
  }
  kept.sort((x, y) => x.location.localeCompare(y.location) || x.start - y.start);

  const findings = [];
  const byCat = {};
  for (const s of kept) (byCat[s.category] ??= []).push(s);
  for (const [cat, list] of Object.entries(byCat)) {
    const active = list.filter(s => !s.context_flags.length);
    const flagged = list.filter(s => s.context_flags.length);
    const rule = RULE_FOR[cat];
    const show = (active.length ? active : flagged).slice(0, 5);
    const evidence = show.map(s => `"${s.text}"`).join(" · ") + (list.length > 5 ? ` (+${list.length - 5} more)` : "");
    const first = show[0];
    if (active.length) {
      findings.push(makeFinding(rule, { evidence, source: first.location, excerpt: first.excerpt, details: { matches: list.length, active: active.length, context_flagged: flagged.length, spans: list.map(({ excerpt: _e, ...s }) => s) } }));
    } else {
      const flagsUsed = [...new Set(flagged.flatMap(s => s.context_flags))];
      findings.push(makeFinding(rule, { evidence, source: first.location, excerpt: first.excerpt, priority: "info", points: 0, context_flags: flagsUsed, details: { matches: list.length, active: 0, context_flagged: flagged.length, note: "All matches appear negated, quoted, or in awareness/training context, so they are not weighted. Review the context yourself.", spans: list.map(({ excerpt: _e, ...s }) => s) } }));
    }
  }
  return { ruleset: LANGUAGE_RULESET, spans: kept, findings };
}
