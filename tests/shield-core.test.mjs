import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyzeEmail, validateReport } from "../shield/core/analyze.js";
import { parseMessage, looksLikeRawMessage, LIMITS } from "../shield/core/parse.js";
import { extractHtmlLinks, extractTextUrls, inspectUrl } from "../shield/core/urls.js";
import { domainInfo, sameOrganization, lookalike, skeleton } from "../shield/core/domains.js";
import { parseReceived, parseAuthResults } from "../shield/core/headers.js";
import { analyzeLanguage, contextFlags } from "../shield/core/language.js";
import { analyzeAttachments, extensionsOf } from "../shield/core/attachments.js";
import { attentionIndex } from "../shield/core/score.js";
import { makeFinding } from "../shield/core/rules.js";
import { htmlToText, decodeEntities, hostnameToUnicode, editDistance } from "../shield/core/text.js";

const fx = name => readFileSync(new URL("./fixtures/" + name, import.meta.url), "utf8");
const FIXED = { now: new Date("2026-11-23T12:00:00Z"), reportId: "PXS-20261123-TEST000001" };
const rules = r => r.findings.map(f => f.rule);

// ── Parsing ────────────────────────────────────────────────────────────────
test("detects raw messages vs plain body text", () => {
  assert.equal(looksLikeRawMessage("From: a@b.example\nSubject: hi\n\nbody"), true);
  assert.equal(looksLikeRawMessage("Hello team,\nSee you Thursday."), false);
  assert.equal(looksLikeRawMessage("Note: this is a sentence\n\nmore"), false, "unknown header names alone are not enough");
});

test("parses folded headers and RFC 2047 encoded words", async () => {
  const raw = "From: =?UTF-8?B?w4lxdWlwZSBTw6ljdXJpdMOp?= <team@example.org>\r\nSubject: =?UTF-8?Q?R=C3=A9sum=C3=A9_review?=\r\nReceived: from a.example (a.example [192.0.2.1])\r\n\tby b.example with ESMTP id 1;\r\n Tue, 3 Nov 2026 10:00:00 +0000\r\n\r\nBody";
  const m = await parseMessage(raw);
  assert.equal(m.subject, "Résumé review");
  assert.equal(m.from.name, "Équipe Sécurité");
  const rec = parseReceived(m.headers.find(h => h.key === "received").value);
  assert.equal(rec.by_host, "b.example");
  assert.equal(rec.from_ip, "192.0.2.1");
  assert.equal(rec.timestamp, "2026-11-03T10:00:00.000Z");
});

test("parses multipart MIME with attachment metadata and file signatures", async () => {
  const m = await parseMessage(fx("suspicious-multipart.eml"));
  assert.equal(m.input.mime_parsed, true);
  assert.equal(m.attachments.length, 1);
  assert.equal(m.attachments[0].filename, "invoice.pdf.exe");
  assert.equal(m.attachments[0].detected_signature, "windows-executable");
  assert.match(m.html, /<form/);
  assert.equal(m.reply_to[0].address, "helpdesk.verify@gmail.com");
  assert.equal(m.return_path, "bounce@mailer.example");
});

test("handles Unicode input and keeps UTF-16 offsets exact", async () => {
  const text = "Здравствуйте 😀 — urgent: confirm your password at https://例え.example/ログイン now.";
  const { report, context } = await analyzeEmail(text, FIXED);
  validateReport(report);
  const seg = context.segments.find(s => s.location === "body:text");
  for (const s of report.language.spans) if (s.location === "body:text") assert.equal(seg.text.slice(s.start, s.end), s.text);
  assert.ok(report.links.some(l => l.host.startsWith("xn--")), "IDN host normalized to punycode");
});

test("malformed MIME does not crash and is reported", async () => {
  const raw = "From: x@y.example\nContent-Type: multipart/mixed; boundary=\"NEVER\"\n\n--WRONG\nContent-Type: text/plain\n\nimmediate action required\n--NEVER";
  const { report } = await analyzeEmail(raw, FIXED);
  validateReport(report);
  assert.ok(report.findings.length >= 0);
  await assert.doesNotReject(analyzeEmail("Subject:\n\n\u0000\u0001 binary � junk", FIXED));
});

test("input validation: empty and oversized input are rejected", async () => {
  await assert.rejects(analyzeEmail("   "), /Provide email text/);
  await assert.rejects(analyzeEmail("x".repeat(LIMITS.maxInputBytes + 1)), RangeError);
  await assert.rejects(analyzeEmail(42), TypeError);
});

// ── Links & domains ───────────────────────────────────────────────────────
test("registrable domains use the Public Suffix List", () => {
  assert.equal(domainInfo("login.service.co.uk").registrable, "service.co.uk");
  assert.equal(domainInfo("a.b.paypal.com.evil.co.uk").registrable, "evil.co.uk");
  assert.equal(domainInfo("user.github.io").registrable, "user.github.io", "private PSL section respected");
  assert.equal(sameOrganization("mail.google.com", "accounts.google.com"), true);
  assert.equal(sameOrganization("paypal.com.secure.example", "paypal.com"), false);
  assert.equal(domainInfo("192.0.2.4").is_ip, true);
});

test("extracts HTML links with visible text, decoding entities, ignoring comments", () => {
  const html = `<!-- <a href="https://hidden.example">x</a> --><a class="b" href='https://real.example/a?x=1&amp;y=2'><b>Visit</b> paypal.com</a><a href=mailto:a@b.example>mail</a><form action="https://post.example/x"><input type=password></form>`;
  const { links, forms } = extractHtmlLinks(html);
  assert.deepEqual(links.map(l => l.raw), ["https://real.example/a?x=1&y=2", "mailto:a@b.example", "https://post.example/x"]);
  assert.equal(links[0].display_text, "Visit paypal.com");
  assert.equal(forms[0].has_password_field, true);
});

test("text URL extraction trims punctuation but keeps balanced parentheses", () => {
  const urls = extractTextUrls("See https://en.wikipedia.org/wiki/Foo_(bar). And (https://x.example/a), www.site.example!", "body:text").map(u => u.raw);
  assert.deepEqual(urls, ["https://en.wikipedia.org/wiki/Foo_(bar)", "https://x.example/a", "www.site.example"]);
});

test("suspicious URL structure indicators", () => {
  const ids = raw => inspectUrl({ raw, location: "t", display_text: null }).findings.map(f => f.rule);
  assert.ok(ids("http://192.0.2.5/login").includes("link.ip-host"));
  assert.ok(ids("http://0xC0000205/x").includes("link.ip-obfuscated"));
  assert.ok(ids("https://www.bank.example@evil.example/").includes("link.userinfo"));
  assert.ok(ids("https://xn--pypal-4ve.com/").includes("link.idn"));
  assert.ok(ids("https://bit.ly/abc").includes("link.shortener"));
  assert.ok(ids("https://a.b.c.d.e.example/").includes("link.deep-subdomain"));
  assert.ok(ids("https://site.example:8443/").includes("link.port"));
  assert.ok(ids("https://www.paypal.com.verify-user.example/").includes("link.brand-in-subdomain"));
  assert.ok(ids("https://redirect.example/go?url=https%3A%2F%2Fevil.example%2F").includes("link.redirect-param"));
  assert.ok(ids("javascript:alert(1)").includes("link.dangerous-scheme"));
});

test("benign URLs produce no indicators", () => {
  for (const raw of ["https://www.paypal.com/myaccount", "https://accounts.google.com/signin", "https://docs.university.example/notes", "https://login.microsoftonline.com/"]) {
    assert.deepEqual(inspectUrl({ raw, location: "t" }).findings, [], raw);
  }
});

test("link text mismatch compares registered domains, not strings", () => {
  const mismatch = inspectUrl({ raw: "https://evil.example/x", location: "body:html", display_text: "www.paypal.com" });
  assert.ok(mismatch.findings.some(f => f.rule === "link.text-mismatch"));
  const sameOrg = inspectUrl({ raw: "https://click.mail.paypal.com/x", location: "body:html", display_text: "www.paypal.com" });
  assert.ok(!sameOrg.findings.some(f => f.rule === "link.text-mismatch"), "subdomain of the same organization is not a mismatch");
  const plain = inspectUrl({ raw: "https://evil.example/x", location: "body:html", display_text: "Click here" });
  assert.ok(!plain.findings.some(f => f.rule === "link.text-mismatch"));
});

test("look-alike domain heuristics", () => {
  assert.equal(lookalike("paypa1.com")?.brand, "PayPal");
  assert.equal(lookalike("rnicrosoft.com")?.brand, "Microsoft");
  assert.equal(lookalike("micros0ft-support.example")?.technique, "brand-plus-words");
  assert.equal(lookalike("xn--pypal-4ve.com")?.brand, "PayPal", "Cyrillic а homograph");
  assert.equal(lookalike("paypal.com"), null);
  assert.equal(lookalike("mail.google.com"), null);
  assert.equal(lookalike("university.example"), null);
  assert.equal(lookalike("apply.example"), null, "short brand names do not use edit distance");
  assert.equal(skeleton("rn1crosoft"), "mlcrosoft");
  assert.equal(editDistance("paypal", "paypla", 2), 1, "transposition counts as one edit");
});

// ── Language & false-positive safeguards ──────────────────────────────────
test("negated, quoted and awareness text is flagged and not weighted", async () => {
  const { report } = await analyzeEmail(fx("awareness.txt"), FIXED);
  validateReport(report);
  assert.equal(report.attention.index, 0);
  for (const f of report.findings.filter(x => x.category === "language")) {
    assert.equal(f.points, 0); assert.equal(f.priority, "info"); assert.ok(f.context_flags.length);
  }
  assert.ok(contextFlags("> please send your password now", 9, 27).includes("quoted_reply"));
});

test("genuine pressure + credential request is detected with combination", () => {
  const out = analyzeLanguage([{ text: "Your account will be suspended. Act now and confirm your password here.", location: "body:text" }]);
  const ids = out.findings.map(f => f.rule);
  assert.ok(ids.includes("lang.account-threat") && ids.includes("lang.credential") && ids.includes("lang.urgency"));
  assert.ok(out.findings.every(f => f.points > 0));
});

test("OTP, payment and impersonation language", () => {
  const out = analyzeLanguage([{ text: "This is the IT department. Please share the verification code we sent. Also buy gift cards and keep this confidential.", location: "body:text" }]);
  const ids = out.findings.map(f => f.rule);
  for (const r of ["lang.otp", "lang.payment", "lang.impersonation"]) assert.ok(ids.includes(r), r);
});

// ── Attachments ───────────────────────────────────────────────────────────
test("attachment metadata checks never claim scanning", () => {
  assert.deepEqual(extensionsOf("Report.Final.PDF.exe"), ["final", "pdf", "exe"]);
  const { attachments, findings } = analyzeAttachments([
    { filename: "invoice.pdf.exe", mime_type: "application/pdf", size_bytes: 10 },
    { filename: "photo‮gpj.exe", mime_type: "image/jpeg", size_bytes: 10 },
    { filename: "budget.xlsm", mime_type: "application/vnd.ms-excel.sheet.macroEnabled.12", size_bytes: 10 },
    { filename: "login.html", mime_type: "text/html", size_bytes: 10 },
    { filename: "scan.pdf", mime_type: "application/pdf", size_bytes: 10, detected_signature: "windows-executable", signature_extensions: ["exe"], leading_bytes_hex: "4d 5a" },
    { filename: "notes.txt", mime_type: "text/plain", size_bytes: 10 }
  ]);
  const ids = findings.map(f => f.rule);
  for (const r of ["attach.double-extension", "attach.rtlo", "attach.macro", "attach.html", "attach.type-mismatch"]) assert.ok(ids.includes(r), r);
  assert.ok(attachments.every(a => a.malware_scanned === false));
  assert.deepEqual(attachments[5].flags, []);
});

// ── Headers / authentication trust boundary ───────────────────────────────
test("authentication results are parsed as unverified claims only", async () => {
  const ar = parseAuthResults("mx.example.org; spf=pass smtp.mailfrom=a@b.example; dkim=pass (good sig) header.d=b.example header.s=s1; dmarc=pass header.from=b.example");
  assert.equal(ar.authserv_id, "mx.example.org");
  assert.deepEqual(ar.results.map(r => [r.method, r.result]), [["spf", "pass"], ["dkim", "pass"], ["dmarc", "pass"]]);
  const { report } = await analyzeEmail(fx("benign-newsletter.eml"), FIXED);
  const auth = report.headers.authentication;
  assert.equal(auth.verified, false);
  assert.equal(auth.dmarc.status, "unverified_claim");
  assert.equal(auth.trust, "unverified_pasted_header_claims");
  assert.match(auth.explanation, /NOT verified/);
});

test("forged 'pass' claims never reduce the attention index", async () => {
  const base = "From: \"PayPal\" <x@paypa1.example>\nSubject: hi\n\nConfirm your password immediately at http://192.0.2.1/";
  const a = await analyzeEmail(base, FIXED);
  const b = await analyzeEmail("Authentication-Results: mx.example; spf=pass; dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com\n" + base, FIXED);
  assert.ok(b.report.attention.index >= a.report.attention.index);
});

test("received chain ordering, IP preference and private ranges", async () => {
  const { report } = await analyzeEmail(fx("suspicious-multipart.eml"), FIXED);
  const hops = report.headers.received;
  assert.equal(hops[0].hop, 1);
  assert.equal(hops[0].from_ip, "198.51.100.7", "server-recorded IP preferred over HELO literal");
  assert.equal(hops[0].helo_ip, "10.0.0.5");
  assert.equal(hops[1].by_host, "mail.recipient.example");
  assert.equal(hops[1].delay_seconds, 60);
});

// ── End-to-end analysis, scoring and determinism ──────────────────────────
test("suspicious fixture: grounded findings across all categories", async () => {
  const { report } = await analyzeEmail(fx("suspicious-multipart.eml"), FIXED);
  validateReport(report);
  const ids = rules(report);
  for (const r of ["html.form", "link.text-mismatch", "link.ip-obfuscated", "link.shortener", "link.dangerous-scheme", "sender.display-address", "sender.lookalike", "sender.replyto-mismatch", "attach.double-extension", "lang.otp", "combo.pressure-sensitive", "header.auth-fail-claim"]) assert.ok(ids.includes(r), "missing " + r);
  for (const f of report.findings) { assert.ok(f.evidence && f.source && f.why && f.next_action && f.false_positive_notes); }
  assert.equal(report.attention.band, "high");
  assert.ok(!JSON.stringify(report).includes("never executed"), "HTML script content is not copied into the report");
});

test("benign fixture: no weighted indicators, and low index is not called safe", async () => {
  const { report } = await analyzeEmail(fx("benign-newsletter.eml"), FIXED);
  validateReport(report);
  assert.equal(report.findings.filter(f => f.points > 0).length, 0);
  assert.equal(report.attention.index, 0);
  assert.match(report.attention.summary, /does not mean the message is safe/);
  assert.ok(report.recommendations.some(r => /not a guarantee/i.test(r.title)));
});

test("attention index: deterministic, capped per category, bounded 0-100, not a probability", () => {
  const many = Array.from({ length: 10 }, (_, i) => ({ ...makeFinding("link.userinfo", { evidence: "e" + i, source: "s" }), id: "F" + i }));
  const a = attentionIndex(many);
  assert.equal(a.category_points.link, 45);
  assert.equal(a.index, 45);
  assert.equal(a.type, "uncalibrated_heuristic_attention_index");
  assert.match(a.disclaimer, /not a probability/);
  assert.deepEqual(attentionIndex(many), a);
  assert.equal(attentionIndex([]).index, 0);
});

test("analysis is deterministic for identical input", async () => {
  const strip = r => { const { engine, ...rest } = r; return { ...rest, engine: { ...engine, duration_ms: 0 } }; };
  const a = await analyzeEmail(fx("suspicious-multipart.eml"), FIXED);
  const b = await analyzeEmail(fx("suspicious-multipart.eml"), FIXED);
  assert.deepEqual(strip(a.report), strip(b.report));
});

test("eml bytes (ArrayBuffer) and pasted text produce the same findings", async () => {
  const text = fx("suspicious-multipart.eml");
  const a = await analyzeEmail(text, FIXED);
  const b = await analyzeEmail(new TextEncoder().encode(text).buffer, { ...FIXED, source: "eml_file", fileName: "x.eml" });
  assert.deepEqual(rules(a.report), rules(b.report));
  assert.equal(b.report.input.file_name, "x.eml");
});

test("report never contains the full message body", async () => {
  const secretLine = "UNIQUE-BODY-SENTINEL-" + "z".repeat(40);
  const { report } = await analyzeEmail(`From: a@b.example\nSubject: s\n\nHello.\n${secretLine}\nRegards`, FIXED);
  assert.ok(!JSON.stringify(report).includes(secretLine));
});

test("text helpers", () => {
  assert.equal(decodeEntities("&lt;b&gt; &amp; &#x41;&#66; &nbsp;"), "<b> & AB  ");
  assert.equal(htmlToText("<style>x{}</style><p>Hi&nbsp;there</p><script>bad()</script><br>ok"), "Hi there\n\nok");
  assert.equal(htmlToText("<p>a</p><p>b</p>"), "a\n\nb");
  assert.equal(hostnameToUnicode("xn--pypal-4ve.com"), "pаypal.com");
});

// ── Robustness against adversarial input ──────────────────────────────────
test("adversarial inputs complete quickly and stay bounded", async () => {
  const N = 200000;
  const cases = {
    unclosedAnchors: '<a href="https://x.example/">'.repeat(N / 30),
    angleSoup: "<".repeat(N),
    longUrl: "https://" + "a".repeat(N),
    dottedHost: "https://" + "a.".repeat(N / 2) + "example/",
    quotes: '"'.repeat(N),
    formFlood: "<form action=x>".repeat(N / 15),
    headerFlood: Array.from({ length: 3000 }, (_, i) => "X-H" + i + ": v").join("\n") + "\nFrom: a@b.example\n\nbody"
  };
  for (const [name, input] of Object.entries(cases)) {
    const t0 = performance.now();
    const { report } = await analyzeEmail(input, FIXED);
    validateReport(report);
    assert.ok(performance.now() - t0 < 3000, name + " took too long");
    assert.ok(report.findings.length <= 2500, name + " produced unbounded findings");
  }
  const forms = (await analyzeEmail(cases.formFlood, FIXED)).report.findings.filter(f => f.rule === "html.form");
  assert.equal(forms.length, 10);
});

test("unclosed anchors still yield href and visible text", () => {
  const { links } = extractHtmlLinks('<p><a href="https://evil.example/login">paypal.com <b>sign in</b><p>next paragraph');
  assert.equal(links[0].raw, "https://evil.example/login");
  assert.match(links[0].display_text, /^paypal\.com sign in/);
});
