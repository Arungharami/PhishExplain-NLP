// Browser integration tests. Run: npm run test:e2e
// Uses playwright-core with an installed Chrome or Edge (set PLAYWRIGHT_CHANNEL=chrome|msedge to choose).
// The dev server applies vercel.json headers, so the production Content-Security-Policy is enforced.
// Set SHIELD_BASE_URL=https://phishexplain-nlp.vercel.app to run the same suite against a deployment.
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { chromium } from "playwright-core";
import { startServer } from "../../scripts/serve.mjs";
import { validateReport } from "../../shield/core/analyze.js";

const PORT = 4190;
const REMOTE = process.env.SHIELD_BASE_URL ? process.env.SHIELD_BASE_URL.replace(/\/$/, "") : null;
const BASE = REMOTE || `http://127.0.0.1:${PORT}`;
const HOST = new URL(BASE).hostname;
let server, browser;

async function launch() {
  const channels = process.env.PLAYWRIGHT_CHANNEL ? [process.env.PLAYWRIGHT_CHANNEL] : ["chrome", "msedge"];
  for (const channel of channels) { try { return await chromium.launch({ channel, headless: true }); } catch { /* try next */ } }
  return null;
}

before(async () => { if (!REMOTE) server = await startServer(PORT); browser = await launch(); });
after(async () => { await browser?.close(); server?.close(); });

/** New page that fails the test on console errors, CSP violations, dialogs or off-origin requests. */
async function openPage(t, path, { viewport } = {}) {
  if (!browser) { t.skip("No Chrome/Edge browser available"); return null; }
  const ctx = await browser.newContext({ viewport: viewport || { width: 1280, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  const problems = [];
  page.on("console", m => { if (m.type() === "error") problems.push("console: " + m.text()); });
  page.on("pageerror", e => problems.push("pageerror: " + e.message));
  page.on("dialog", d => { if (page.acceptDialogs) return d.accept(); problems.push("dialog: " + d.message()); return d.dismiss(); });
  page.on("request", r => { const u = new URL(r.url()); if (![HOST, ""].includes(u.hostname) && !u.protocol.startsWith("blob") && !u.protocol.startsWith("data")) problems.push("off-origin request: " + r.url()); });
  page.problems = problems;
  page.ctx = ctx;
  await page.goto(BASE + path);
  await waitReady(page);
  return page;
}
/** Shield pages set body[data-ready] once their module has initialized; research pages do not use it. */
async function waitReady(page) { if (await page.$("script[src=\"/shield.js\"]")) await page.waitForSelector("body[data-ready]", { state: "attached", timeout: 10000 }); }
const done = async page => { const p = page.problems.filter(x => !/favicon/.test(x)); await page.ctx.close(); assert.deepEqual(p, []); };

test("scanner analyzes a suspicious sample end to end", async t => {
  const page = await openPage(t, "/security/"); if (!page) return;
  await page.click('[data-sample="credential"]');
  await page.click("#analyze");
  await page.waitForSelector("#result .finding");
  const titles = await page.$$eval("#result .finding .ftitle", els => els.map(e => e.textContent));
  assert.ok(titles.includes("Link text shows a different domain than the real destination"), titles.join("|"));
  assert.ok(titles.includes("Request for passwords or sign-in details"));
  assert.match(await page.textContent("#result h2"), /High attention|Review recommended/);
  assert.match(await page.textContent("#scan-status"), /Analysis complete/);
  // Expand a finding and check explanation fields
  await page.click("#result .finding summary");
  const body = await page.textContent("#result .finding[open] .fbody");
  for (const k of ["Evidence", "Why it matters", "Could be legitimate if", "Recommended action"]) assert.ok(body.includes(k), k);
  await done(page);
});

test("benign and hard-negative samples are not over-flagged", async t => {
  const page = await openPage(t, "/security/"); if (!page) return;
  for (const id of ["benign", "awareness"]) {
    await page.click(`[data-sample="${id}"]`);
    await page.click("#analyze");
    await page.waitForFunction(() => /Analysis complete/.test(document.querySelector("#scan-status").textContent));
    assert.match(await page.textContent("#result h2"), /No listed indicators/, id);
  }
  await done(page);
});

test("imports an .eml file and exports a valid JSON, CSV and HTML report", async t => {
  const page = await openPage(t, "/security/"); if (!page) return;
  await page.click("#tab-file");
  await page.setInputFiles("#file-input", "tests/fixtures/suspicious-multipart.eml");
  await page.click("#analyze");
  await page.waitForSelector("#result .finding");
  const grab = async label => { const [dl] = await Promise.all([page.waitForEvent("download"), page.click(`#result button:text-is("${label}")`)]); return readFileSync(await dl.path(), "utf8"); };
  const report = JSON.parse(await grab("JSON"));
  validateReport(report);
  assert.equal(report.input.source, "eml_file");
  assert.equal(report.input.file_name, "suspicious-multipart.eml");
  assert.ok(report.attachments.some(a => a.filename === "invoice.pdf.exe"));
  const csv = await grab("CSV");
  assert.match(csv.split("\r\n")[0], /^"report_id","finding_id","priority"/);
  const html = await grab("HTML report");
  assert.doesNotMatch(html, /<script/i);
  assert.match(html, /Email Inspection Report/);
  await done(page);
});

test("hostile HTML email is displayed inertly (no script execution)", async t => {
  const page = await openPage(t, "/security/"); if (!page) return;
  await page.fill("#email-input", `From: "<img src=x onerror=alert(1)>" <a@evil.example>\nSubject: <script>alert(2)</script>\nContent-Type: text/html\n\n<script>alert(3)</script><img src=x onerror=alert(4)><a href="javascript:alert(5)">paypal.com</a> confirm your password now`);
  await page.click("#analyze");
  await page.waitForSelector("#result .finding");
  assert.equal(await page.$$eval("#result img, #result script", e => e.length), 0);
  assert.ok((await page.textContent("#result")).includes("<script>alert(2)</script>"), "subject shown as literal text");
  await done(page);
});

test("analysis, links, headers and reports pages use the current scan", async t => {
  const page = await openPage(t, "/security/"); if (!page) return;
  await page.click('[data-sample="credential"]');
  await page.click("#analyze");
  await page.waitForSelector("#result .finding");

  await page.goto(BASE + "/security/analysis/");

  await waitReady(page);
  await page.waitForSelector("#tier-observed .finding");
  assert.ok(await page.$$eval("#tier-heuristic .finding", e => e.length) > 0);
  assert.ok(await page.$$eval("#marked mark", e => e.length) > 0, "evidence highlighted");
  await page.waitForFunction(() => /unavailable/i.test(document.querySelector("#ai-status").textContent));
  assert.match(await page.textContent("#tier-intel"), /not run/i);

  await page.goto(BASE + "/security/links/");

  await waitReady(page);
  await page.click("#use-current");
  await page.waitForSelector("#url-results article");
  assert.match(await page.textContent("#url-results"), /account-review\.example/);
  await page.waitForFunction(() => /unavailable/i.test(document.querySelector("#rep-config").textContent));
  assert.equal(await page.isVisible("#rep-controls"), false);

  await page.goto(BASE + "/security/headers/");

  await waitReady(page);
  await page.click("#hdr-current");
  await page.waitForSelector("#hdr-hops .timeline li");
  assert.match(await page.textContent("#hdr-auth"), /Unverified claim/);

  await page.goto(BASE + "/security/reports/");

  await waitReady(page);
  await page.waitForSelector("#report-view .finding");
  await done(page);
});

test("header analyzer parses a headers-only paste", async t => {
  const page = await openPage(t, "/security/headers/"); if (!page) return;
  await page.fill("#header-input", readFileSync("tests/fixtures/benign-newsletter.eml", "utf8").split(/\r?\n\r?\n/)[0]);
  await page.click("#hdr-analyze");
  await page.waitForSelector("#hdr-hops .timeline li");
  const auth = await page.textContent("#hdr-auth");
  assert.match(auth, /pass/); assert.match(auth, /Unverified claim/); assert.doesNotMatch(auth, /\bVerified\b(?! claim)/);
  await done(page);
});

test("opt-in local history, dashboard workflow and deletion", async t => {
  const page = await openPage(t, "/security/dashboard/"); if (!page) return;
  assert.equal(await page.isVisible("#history-disabled"), true);
  await page.goto(BASE + "/security/settings/");
  await waitReady(page);
  await page.check("#set-history");
  await page.goto(BASE + "/security/");
  await waitReady(page);
  await page.click('[data-sample="bec"]');
  await page.click("#analyze");
  await page.waitForSelector("#result .finding");
  await page.click('#result button:text-is("Save to history")');
  await page.goto(BASE + "/security/dashboard/");
  await waitReady(page);
  await page.waitForSelector("#history-rows tr");
  assert.match(await page.textContent("#dash-stats"), /1\s*Saved analyses/);
  await page.selectOption("#history-rows select", "needs_verification");
  await page.waitForFunction(() => /Status updated/.test(document.querySelector("#dash-status").textContent));
  await page.goto(BASE + "/security/settings/");
  await waitReady(page);
  page.acceptDialogs = true; // confirm() for "Delete all Shield data"
  await page.click("#delete-all");
  await page.waitForFunction(() => /deleted/.test(document.querySelector("#set-status").textContent));
  await page.goto(BASE + "/security/dashboard/");
  await waitReady(page);
  assert.equal(await page.isVisible("#history-disabled"), true);
  await done(page);
});

test("mobile layout: menu works and there is no horizontal overflow", async t => {
  const page = await openPage(t, "/security/", { viewport: { width: 390, height: 844 } }); if (!page) return;
  assert.equal(await page.isVisible("#site-nav"), false);
  await page.click("#menu-btn");
  assert.equal(await page.getAttribute("#menu-btn", "aria-expanded"), "true");
  assert.equal(await page.isVisible('#site-nav a[href="/security/links/"]'), true);
  await page.keyboard.press("Escape");
  assert.equal(await page.isVisible("#site-nav"), false);
  const overflowOf = () => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  for (const id of ["credential", "attachment", "otp"]) {
    await page.click(`[data-sample="${id}"]`); await page.click("#analyze"); await page.waitForSelector("#result .finding");
    await page.$$eval("#result details.finding", ds => ds.forEach(d => { d.open = true; }));
    assert.ok(await overflowOf() <= 1, `scanner results for ${id} overflow by ${await overflowOf()}px`);
  }
  for (const p of ["/", "/security/", "/security/headers/", "/security/settings/", "/security/dashboard/", "/security/analysis/", "/security/reports/", "/security/links/"]) {
    await page.goto(BASE + p);
    await waitReady(page);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 1, `${p} overflows by ${overflow}px`);
  }
  await done(page);
});

test("keyboard: skip link and tabs are operable", async t => {
  const page = await openPage(t, "/security/"); if (!page) return;
  await page.keyboard.press("Tab");
  assert.equal(await page.evaluate(() => document.activeElement.className), "skip");
  await page.focus("#tab-paste");
  await page.keyboard.press("ArrowRight");
  assert.equal(await page.evaluate(() => document.activeElement.id), "tab-file");
  assert.equal(await page.isVisible("#panel-file"), true);
  await done(page);
});

test("homepage and research routes load without errors", async t => {
  for (const p of ["/", "/nlp/", "/lab/", "/annotation/", "/evaluation/", "/course/", "/dataset/"]) {
    const page = await openPage(t, p); if (!page) return;
    await page.waitForLoadState("networkidle");
    if (p === "/") assert.ok(await page.$$eval("#glossary dt", e => e.length) >= 9);
    if (p === "/lab/") await page.waitForSelector("#lab-email");
    // Research overview loads Google Fonts by design; ignore those off-origin requests only there.
    page.problems = page.problems.filter(x => !/fonts\.(googleapis|gstatic)\.com/.test(x));
    await done(page);
  }
});
