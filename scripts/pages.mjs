#!/usr/bin/env node
// Generates the static HTML for the homepage and PhishExplain Shield product pages from one shared shell.
// Usage: node scripts/pages.mjs          (write files)
//        node scripts/pages.mjs --check  (fail if committed HTML is out of date; used in CI)
import { writeFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";

const SHIELD_NAV = [["/security/", "Scanner"], ["/security/dashboard/", "Dashboard"], ["/security/links/", "Links"], ["/security/headers/", "Headers"], ["/security/analysis/", "Analysis"], ["/security/reports/", "Reports"], ["/security/settings/", "Settings"]];
const RESEARCH_NAV = [["/lab/", "Lab"], ["/annotation/", "Annotation"], ["/evaluation/", "Evaluation"], ["/course/", "Course"], ["/nlp/", "Overview"]];
const LOGO = `<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M16 2.5 28 7v8.3c0 7.3-4.7 11.8-12 14.2C8.7 27.1 4 22.6 4 15.3V7l12-4.5Z" stroke="currentColor" stroke-width="1.8"/><path d="m10.5 16 3.4 3.4 7.6-8" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

const navLinks = (items, current) => items.map(([href, label]) => `<a href="${href}"${href === current ? ' aria-current="page"' : ""}>${label}</a>`).join("");

function shell({ route, title, description, page, body, head = "" }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#070d17">
<meta name="description" content="${description}">
<meta name="referrer" content="strict-origin-when-cross-origin">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<title>${title}</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/shield.css">
<script type="module" src="/shield.js"></script>${head}
</head>
<body data-page="${page}">
<a class="skip" href="#main">Skip to content</a>
<header class="site-header">
  <div class="wrap header-row">
    <a class="brand" href="/">${LOGO}<span>PhishExplain <span class="accent">Shield</span><small>Email threat analysis</small></span></a>
    <button class="menu-btn" id="menu-btn" type="button" aria-expanded="false" aria-controls="site-nav">Menu</button>
    <nav class="nav" id="site-nav" aria-label="Main">
      <div class="nav-group shield"><span class="nav-label">Shield</span>${navLinks(SHIELD_NAV, route)}</div>
      <span class="nav-sep" aria-hidden="true"></span>
      <div class="nav-group research"><span class="nav-label">Research Lab</span>${navLinks(RESEARCH_NAV, route)}</div>
    </nav>
  </div>
</header>
<main id="main" tabindex="-1">
${body}
</main>
<footer class="site-footer">
  <div class="wrap footer-row">
    <div><strong>PhishExplain Shield</strong> (beta) · Intelligent Email Threat Analysis. Clear Evidence. Safer Decisions.<br>Manual, evidence-based analysis. Never a guarantee of safety. Product owner: Arun Kumar Gharami.</div>
    <div class="footer-links"><a href="/security/settings/#privacy">Privacy</a><a href="/security/#limitations">Limitations</a><a href="/course/">CAP 6640 research</a><a href="https://github.com/Arungharami/PhishExplain-NLP" rel="noopener noreferrer" target="_blank">Source code</a></div>
  </div>
</footer>
</body>
</html>
`;
}

const head = (kicker, h1, lead, extra = "", research = false) => `<section class="wrap page-head"><span class="kicker${research ? " research" : ""}">${kicker}</span><h1>${h1}</h1><p class="lead">${lead}</p>${extra}</section>`;
const noReport = `<div class="card hidden" id="no-report"><h2>No analysis loaded</h2><p class="muted">Run a scan in the <a href="/security/">Email Threat Scanner</a> first. The current analysis is kept only in this browser tab.</p></div>`;

const PAGES = [];

// ── Home ───────────────────────────────────────────────────────────────────
PAGES.push({ route: "/", file: "index.html", page: "home", title: "PhishExplain Shield — Intelligent Email Threat Analysis", description: "Analyze suspicious emails privately in your browser. See grounded evidence for sender, link, attachment and social-engineering indicators, with clear next steps.", body: `
<section class="wrap hero">
  <div>
    <span class="kicker">Email threat analysis · Public beta</span>
    <h1>Intelligent email threat analysis. <em>Clear evidence.</em> Safer decisions.</h1>
    <p class="tagline">Paste a suspicious email or open an <code>.eml</code> file. Shield parses the message in your browser, inspects every link without visiting it, checks sender consistency and attachment metadata, and explains each indicator in plain language.</p>
    <div class="hero-actions"><a class="btn primary" href="/security/">Scan an email</a><a class="btn" href="/security/links/">Inspect a link</a><a class="btn" href="/security/headers/">Analyze headers</a></div>
    <div class="status-strip"><span class="chip ok"><span class="dot"></span>Runs locally — no upload by default</span><span class="chip">No account needed</span><span class="chip warn"><span class="dot"></span>Heuristic index is uncalibrated</span></div>
  </div>
  <aside class="preview" aria-label="Example of the kind of evidence Shield shows (synthetic example)">
    <div class="row"><strong>Example findings</strong><span class="chip muted">Synthetic sample</span></div>
    <div class="preview-row"><span class="pri high">High</span><div><b>Link text shows a different domain than the real destination</b><span class="muted">Text "paypal.com/signin" → goes to secure-check.example</span></div></div>
    <div class="preview-row"><span class="pri high">High</span><div><b>Request for a one-time code</b><span class="muted">“reply with the verification code”</span></div></div>
    <div class="preview-row"><span class="pri medium">Medium</span><div><b>Replies go to a different organization</b><span class="muted">From paypa1-security.example → Reply-To gmail.com</span></div></div>
    <div class="preview-row"><span class="pri info">Info</span><div><b>SPF / DKIM / DMARC</b><span class="muted">Shown as unverified header claims — never as verified</span></div></div>
  </aside>
</section>
<section class="wrap section">
  <div class="grid grid-2">
    <article class="card area-card"><h3><span class="chip ok">Product</span> PhishExplain Shield</h3><p class="muted">Usable email security analysis for individuals and authorized security reviewers.</p>
      <ul class="feature-list"><li>Paste text, raw headers + body, or import <code>.eml</code> / <code>.txt</code></li><li>MIME parsing, HTML link extraction and link-text mismatch detection</li><li>Registered-domain comparison (Public Suffix List), look-alike and punycode checks</li><li>From / Reply-To / Return-Path consistency and Received-hop timeline</li><li>Attachment name, type and file-signature checks (no malware scanning)</li><li>Social-engineering cues with negation and quotation safeguards</li><li>JSON, CSV, HTML and print-to-PDF reports; optional local history</li></ul>
      <div class="row mt-16"><a class="btn primary small" href="/security/">Open scanner</a><a class="btn small" href="/security/dashboard/">Dashboard</a></div></article>
    <article class="card area-card"><h3><span class="chip ai">Research</span> NLP Research Lab</h3><p class="muted">Independent CAP 6640 (Florida Atlantic University) study comparing a classical extractor with a prompted transformer against human-reviewed labels.</p>
      <ul class="feature-list research"><li>Live rule vs. transformer comparison on synthetic emails</li><li>Human gold annotation studio with exact span offsets</li><li>Held-out evaluation that refuses unreviewed data</li><li>Course submission audit and research documentation</li></ul>
      <p class="tiny muted mt-12">Research results are reported separately and are not used as evidence of Shield's detection performance.</p>
      <div class="row mt-12"><a class="btn small" href="/lab/">Research Lab</a><a class="btn small" href="/course/">Course center</a></div></article>
  </div>
</section>
<section class="wrap section">
  <div class="grid grid-2">
    <article class="card"><h2>What Shield does</h2><ul class="feature-list"><li>Reads the message structure and shows <strong>observed facts</strong> (for example, "this link uses HTTP").</li><li>Applies documented <strong>heuristics</strong> (for example, "this domain resembles paypal.com") and labels them as interpretations.</li><li>Shows <strong>external intelligence</strong> only when a configured provider actually returns a result, with provider name and timestamp.</li><li>Keeps an optional AI explanation separate, consent-based and grounded in exact quotes.</li></ul></article>
    <article class="card"><h2>What Shield does not do</h2><ul class="feature-list no"><li>It does not verify SPF, DKIM or DMARC from pasted headers.</li><li>It does not open links, follow redirects or scan attachments for malware.</li><li>It does not connect to your inbox, block, quarantine or delete mail.</li><li>Its attention index is not a probability and a low value never means "safe".</li><li>Detection accuracy has not yet been measured on a validated benchmark.</li></ul></article>
  </div>
</section>
<section class="wrap section" id="learn">
  <h2>Understand the threats</h2>
  <dl class="glossary" id="glossary"></dl>
  <p class="small muted mt-14">If you think you have already responded to a phishing email, change your password from the official website, enable multi-factor authentication, and contact your bank or IT team. U.S. users can also report phishing at <a href="https://reportfraud.ftc.gov/" rel="noopener noreferrer" target="_blank">reportfraud.ftc.gov</a>.</p>
</section>` });

// ── Scanner ────────────────────────────────────────────────────────────────
PAGES.push({ route: "/security/", file: "security/index.html", page: "scanner", title: "Email Threat Scanner — PhishExplain Shield", description: "Paste an email or import an .eml file to see grounded sender, link, attachment and language indicators. Runs in your browser.", body: `
${head("Email threat scanner", "Inspect before you interact.", "Paste the message body, the full raw message (headers and body), or import an <code>.eml</code>/<code>.txt</code> file. Analysis runs in this browser; nothing is uploaded and no link is opened.")}
<div class="wrap split">
  <section class="card no-print" aria-labelledby="input-h">
    <div class="card-head"><div><h2 id="input-h">Email to inspect</h2><p class="card-sub">Local analysis · up to 5 MB</p></div><span class="chip ok"><span class="dot"></span>Local</span></div>
    <div class="tabs" role="tablist" aria-label="Input method"><button class="tab" role="tab" id="tab-paste" aria-selected="true" aria-controls="panel-paste" type="button">Paste</button><button class="tab" role="tab" id="tab-file" aria-selected="false" aria-controls="panel-file" type="button" tabindex="-1">Import file</button></div>
    <div id="panel-paste" role="tabpanel" aria-labelledby="tab-paste">
      <label class="field" for="email-input">Email content (body only, or full headers + body)</label>
      <textarea id="email-input" class="textarea" spellcheck="false" autocomplete="off" aria-describedby="input-meta privacy-note" placeholder="From: Example Sender &lt;sender@example.com&gt;&#10;Subject: ...&#10;&#10;Message body..."></textarea>
      <p class="hint" id="input-meta">0 characters</p>
    </div>
    <div id="panel-file" role="tabpanel" aria-labelledby="tab-file" hidden>
      <div class="dropzone" id="dropzone"><p><strong>Drop an .eml or .txt file here</strong></p><p class="small">or</p><label class="btn" for="file-input">Choose file</label><input type="file" id="file-input" class="sr-only" accept=".eml,.txt,message/rfc822,text/plain"><p class="hint" id="file-meta">No file selected. Files are read locally and never uploaded.</p></div>
    </div>
    <p class="field mb-6">Synthetic examples</p>
    <div class="sample-row" id="samples"></div>
    <div class="row mt-16"><button class="btn primary" id="analyze" type="button">Analyze email</button><button class="btn" id="clear" type="button">Clear</button></div>
    <p class="hint mt-12" id="privacy-note">Private by default: the message stays in this tab. Optional reputation and AI checks are separate and ask for consent first.</p>
    <p id="scan-status" class="small" role="status" aria-live="polite"></p>
  </section>
  <section aria-labelledby="results-h" id="results-region">
    <h2 id="results-h" class="sr-only">Analysis results</h2>
    <div class="card" id="empty-state"><h3>Ready when you are</h3><p class="muted">Run an analysis to see the attention index, every observed indicator with its evidence, link destinations, sender and authentication claims, and safer next steps.</p></div>
    <div id="result" class="hidden"></div>
  </section>
</div>
<section class="wrap section" id="limitations"><div class="card"><h2>Limitations</h2><ul class="feature-list no" id="limitations-list"></ul></div></section>` });

// ── Dashboard ─────────────────────────────────────────────────────────────
PAGES.push({ route: "/security/dashboard/", file: "security/dashboard/index.html", page: "dashboard", title: "Security Dashboard — PhishExplain Shield", description: "Review saved analyses, track investigation status and analyst notes. Stored only in this browser when enabled.", body: `
${head("Security dashboard", "Your saved investigations", "Counters on this page come only from analyses you chose to save in this browser. Workflow states describe your review progress, not whether a message is malicious.", `<div class="status-strip"><span class="chip warn"><span class="dot"></span>No inbox monitoring — manual submissions only</span><span class="chip">Stored locally in this browser</span></div>`)}
<div class="wrap">
  <div class="card hidden" id="history-disabled"><h2>Local history is off</h2><p class="muted">Scan reports are not saved by default. To track investigations here, enable local history in <a href="/security/settings/">Settings</a>. Saved reports contain sender details, URLs and short evidence excerpts, but not the full message.</p></div>
  <div id="dashboard" class="hidden">
    <div class="grid grid-4" id="dash-stats"></div>
    <div class="card mt-18">
      <div class="card-head"><div><h2>Investigations</h2><p class="card-sub">Sorted by most recently updated</p></div><div class="row"><label class="sr-only" for="status-filter">Filter by status</label><select id="status-filter" class="select w-auto"></select><button class="btn small" id="export-history" type="button">Export all (JSON)</button></div></div>
      <div class="table-wrap"><table><thead><tr><th scope="col">Saved</th><th scope="col">Subject / sender</th><th scope="col">Index</th><th scope="col">Findings</th><th scope="col">Status</th><th scope="col">Actions</th></tr></thead><tbody id="history-rows"></tbody></table></div>
      <p class="hint" id="history-empty"></p>
    </div>
    <div class="card hidden" id="notes-card"><div class="card-head"><h2 id="notes-title">Analyst notes</h2><button class="btn small" id="notes-close" type="button">Close</button></div><ul id="notes-list" class="stack small"></ul><label class="field" for="note-input">Add a note</label><textarea id="note-input" class="input" rows="3" maxlength="2000"></textarea><div class="row mt-10"><button class="btn primary small" id="note-add" type="button">Add note</button></div></div>
  </div>
  <p id="dash-status" class="small" role="status" aria-live="polite"></p>
</div>` });

// ── Links ─────────────────────────────────────────────────────────────────
PAGES.push({ route: "/security/links/", file: "security/links/index.html", page: "links", title: "URL Inspection Center — PhishExplain Shield", description: "Inspect URL structure without visiting it: registered domain, punycode, look-alikes, shorteners, IP hosts and redirects. Optional provider reputation lookups.", body: `
${head("URL inspection center", "Look at a link without opening it.", "Paste one URL per line, or load the links from your current scan. Shield parses each URL as text — it never visits, resolves or follows it.")}
<div class="wrap">
  <section class="card" aria-labelledby="url-h"><h2 id="url-h">URLs to inspect</h2>
    <label class="field" for="url-input">One URL per line (http, https or www.)</label>
    <textarea id="url-input" class="textarea min-140" spellcheck="false" placeholder="https://example.com/login"></textarea>
    <div class="row mt-12"><button class="btn primary" id="inspect" type="button">Inspect URLs</button><button class="btn" id="use-current" type="button">Load links from current scan</button></div>
    <p id="url-status" class="small" role="status" aria-live="polite"></p>
  </section>
  <div id="url-results" class="stack mt-18"></div>
  <section class="card mt-18" aria-labelledby="rep-h">
    <div class="card-head"><div><h2 id="rep-h">External reputation lookup</h2><p class="card-sub">Optional · server-side · allow-listed providers only</p></div><span class="chip muted" id="rep-config">Checking configuration…</span></div>
    <div class="alert info">Selected URLs (with any embedded user names or passwords removed) are sent from our server to the configured providers' APIs. Providers may log the queries. Shield never fetches the URL itself. A "not listed" response is not a safety verdict.</div>
    <div id="rep-controls" class="hidden">
      <label class="check"><input type="checkbox" id="rep-consent"> I consent to sending these URLs to the listed third-party reputation providers.</label>
      <label class="field hidden" id="rep-key-field" for="rep-key">Shield access key (kept only for this tab)<input id="rep-key" class="input" type="password" autocomplete="off"></label>
      <button class="btn" id="rep-run" type="button" disabled>Check reputation</button>
    </div>
    <p id="rep-status" class="small" role="status" aria-live="polite"></p>
    <div id="rep-results"></div>
  </section>
</div>` });

// ── Headers ───────────────────────────────────────────────────────────────
PAGES.push({ route: "/security/headers/", file: "security/headers/index.html", page: "headers", title: "Email Header Analyzer — PhishExplain Shield", description: "Visualize Received hops, compare From, Reply-To and Return-Path, and read SPF, DKIM and DMARC claims with correct trust boundaries.", body: `
${head("Email header analyzer", "Follow the route. Question the claims.", "Paste the full original headers (in Gmail: ⋮ → Show original; in Outlook: File → Properties → Internet headers). Shield parses the route and authentication claims locally.", `<div class="alert warn mt-16 mw-820"><strong>Trust boundary:</strong> SPF, DKIM and DMARC results in pasted headers are <strong>unverified claims</strong>. Anyone can write or edit these headers. Shield does not perform authentication checks and never reports them as verified.</div>`)}
<div class="wrap">
  <section class="card" aria-labelledby="hdr-h"><h2 id="hdr-h">Headers</h2>
    <label class="field" for="header-input">Raw headers (a body is optional)</label>
    <textarea id="header-input" class="textarea min-200" spellcheck="false" placeholder="Received: from ...&#10;Authentication-Results: ...&#10;From: ...&#10;Subject: ..."></textarea>
    <div class="row mt-12"><button class="btn primary" id="hdr-analyze" type="button">Analyze headers</button><button class="btn" id="hdr-current" type="button">Use current scan</button></div>
    <p id="hdr-status" class="small" role="status" aria-live="polite"></p>
  </section>
  <div id="hdr-results" class="hidden mt-18">
    <div class="grid grid-2"><section class="card" aria-labelledby="snd-h"><h2 id="snd-h">Sender identity</h2><div id="hdr-sender"></div></section><section class="card" aria-labelledby="auth-h"><h2 id="auth-h">Authentication claims <span class="chip warn">Unverified</span></h2><div id="hdr-auth"></div></section></div>
    <section class="card" aria-labelledby="hop-h"><h2 id="hop-h">Received route (oldest first)</h2><p class="card-sub">Each relay adds a Received header at the top. Only the hops added by your own provider's servers are trustworthy; earlier hops can be forged by the sender.</p><div id="hdr-hops" class="mt-14"></div></section>
    <section class="card" aria-labelledby="hf-h"><h2 id="hf-h">Header findings</h2><div id="hdr-findings" class="findings"></div></section>
  </div>
</div>` });

// ── Analysis ──────────────────────────────────────────────────────────────
PAGES.push({ route: "/security/analysis/", file: "security/analysis/index.html", page: "analysis", title: "Explainable Threat Analysis — PhishExplain Shield", description: "See the evidence behind each indicator, separated into observed facts, heuristic interpretations, external intelligence and optional AI analysis.", body: `
${head("Explainable threat analysis", "Evidence, separated by how much it can be trusted.", "Observed facts, heuristic interpretations, provider intelligence and AI judgments are kept apart so they are never presented as interchangeable.")}
<div class="wrap">
  ${noReport}
  <div id="analysis" class="hidden">
    <div class="card"><div class="card-head"><div><h2 id="an-title">Current analysis</h2><p class="card-sub" id="an-sub"></p></div><div class="row"><a class="btn small" href="/security/reports/">Export report</a></div></div><div id="an-summary"></div></div>
    <div class="grid grid-2 mt-18">
      <section class="tier observed" aria-labelledby="t1"><div class="tier-head"><span class="chip ok">1</span><h3 id="t1">Observed indicators</h3></div><p class="small muted">Facts read directly from the message structure.</p><div id="tier-observed" class="findings"></div></section>
      <section class="tier heuristic" aria-labelledby="t2"><div class="tier-head"><span class="chip warn">2</span><h3 id="t2">Heuristic interpretation</h3></div><p class="small muted">Rule-based judgments about wording and resemblance. Can be wrong.</p><div id="tier-heuristic" class="findings"></div></section>
      <section class="tier intel" aria-labelledby="t3"><div class="tier-head"><span class="chip danger">3</span><h3 id="t3">Verified external intelligence</h3></div><p class="small muted">Only results actually returned by a configured provider.</p><div id="tier-intel"></div></section>
      <section class="tier ai" aria-labelledby="t4"><div class="tier-head"><span class="chip ai">AI</span><h3 id="t4">AI-assisted contextual analysis</h3></div><p class="small muted">Optional. Model judgments grounded in exact quotes — not verified facts.</p><div id="tier-ai"></div>
        <div id="ai-controls" class="hidden mt-12"><div class="alert info small">The analyzed message text (up to 12,000 characters) will be sent to the configured model provider (OpenAI) through our server. Do not send messages containing other people's private data unless you are authorized.</div><label class="check"><input type="checkbox" id="ai-consent"> I consent to sending this message text to the AI provider.</label><label class="field" for="ai-key">Shield access key (kept only for this tab)<input id="ai-key" class="input" type="password" autocomplete="off"></label><button class="btn ai" id="ai-run" type="button" disabled>Run AI analysis</button></div>
        <p id="ai-status" class="small" role="status" aria-live="polite"></p></section>
    </div>
    <section class="card mt-18" aria-labelledby="txt-h"><div class="card-head"><div><h2 id="txt-h">Message text with evidence highlighted</h2><p class="card-sub">Displayed as plain text. HTML is never rendered.</p></div><label class="sr-only" for="seg-select">Message part</label><select id="seg-select" class="select w-auto"></select></div><div id="marked" class="marked" tabindex="0" aria-label="Message text with highlighted evidence"></div><div class="legend"><span><i class="l-pressure"></i>Pressure / threat</span><span><i class="l-sensitive"></i>Credentials / codes</span><span><i class="l-other"></i>Payment / impersonation</span><span><i class="l-flagged"></i>Negated or quoted (not weighted)</span><span><i class="l-ai"></i>AI-quoted</span></div></section>
  </div>
</div>` });

// ── Reports ───────────────────────────────────────────────────────────────
PAGES.push({ route: "/security/reports/", file: "security/reports/index.html", page: "reports", title: "Reports & Exports — PhishExplain Shield", description: "Export inspection reports as JSON, CSV, standalone HTML or PDF (via print). Generated locally.", body: `
${head("Reports & exports", "Share the evidence, not the guesswork.", "Reports are generated in your browser. Exports include sender details, URLs and short evidence excerpts, but never the full message body and never access keys.")}
<div class="wrap">
  ${noReport}
  <div id="report-area" class="hidden">
    <div class="card no-print"><div class="card-head"><div><h2>Export</h2><p class="card-sub" id="rp-sub"></p></div></div>
      <div class="row"><button class="btn primary" id="ex-html" type="button">Download HTML report</button><button class="btn" id="ex-print" type="button">Print / save as PDF</button><button class="btn" id="ex-json" type="button">Download JSON</button><button class="btn" id="ex-csv" type="button">Download CSV (findings)</button></div>
      <p class="hint">PDF export uses your browser's print dialog ("Save as PDF"), which keeps the report on your device.</p></div>
    <div id="report-view" class="mt-18"></div>
  </div>
  <section class="card no-print mt-18"><h2>Open a saved JSON report</h2><p class="muted small">Load a report previously exported from Shield to view or re-export it. The file is validated and read locally.</p><label class="btn" for="import-report">Choose JSON report</label><input type="file" id="import-report" class="sr-only" accept=".json,application/json"><p id="rp-status" class="small" role="status" aria-live="polite"></p></section>
</div>` });

// ── Settings ──────────────────────────────────────────────────────────────
PAGES.push({ route: "/security/settings/", file: "security/settings/index.html", page: "settings", title: "Settings & Privacy — PhishExplain Shield", description: "Control local history, retention, access keys and data deletion. See which optional integrations are configured.", body: `
${head("Settings & privacy", "You decide what is kept.", "Shield works without an account and keeps nothing by default. These settings apply only to this browser.")}
<div class="wrap grid grid-2">
  <section class="card" aria-labelledby="st-hist"><h2 id="st-hist">Local scan history</h2>
    <p class="small muted">When enabled, each scan you choose to save is stored in this browser's local storage (not encrypted by Shield, not synced, not sent anywhere). Saved reports include sender addresses, subjects, URLs and short evidence excerpts — not the full message.</p>
    <label class="check"><input type="checkbox" id="set-history"> Save scan reports in this browser so I can track investigations on the dashboard.</label>
    <label class="field" for="set-retention">Delete saved reports automatically after<select id="set-retention" class="select"><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option><option value="0">Never (until I delete them)</option></select></label>
    <label class="check"><input type="checkbox" id="set-autosave"> Save every completed scan automatically (otherwise use "Save to history").</label>
    <p id="set-status" class="small" role="status" aria-live="polite"></p>
  </section>
  <section class="card" aria-labelledby="st-key"><h2 id="st-key">Shield access key</h2>
    <p class="small muted">Optional reputation and AI checks are protected by an access key issued by the deployment owner. The key is kept in this tab's session storage only and is cleared when the tab closes. It is never included in reports.</p>
    <label class="field" for="set-key">Access key<input id="set-key" class="input" type="password" autocomplete="off"></label>
    <div class="row"><button class="btn small" id="key-save" type="button">Use for this session</button><button class="btn small" id="key-clear" type="button">Forget key</button></div>
  </section>
  <section class="card" aria-labelledby="st-svc"><h2 id="st-svc">Service status</h2><p class="small muted">Reported live by this deployment. Unavailable services never block the local scanner.</p><div id="svc-status" class="stack small"></div></section>
  <section class="card" aria-labelledby="st-int"><h2 id="st-int">Accounts & integrations</h2>
    <div class="table-wrap"><table><thead><tr><th scope="col">Capability</th><th scope="col">Status</th></tr></thead><tbody>
      <tr><td>User accounts &amp; cloud history</td><td><span class="chip muted">Not available</span></td></tr>
      <tr><td>Organization workspaces / team access</td><td><span class="chip muted">Not available</span></td></tr>
      <tr><td>Gmail read-only inspection (OAuth)</td><td><span class="chip muted">Planned — not implemented</span></td></tr>
      <tr><td>Microsoft 365 / Outlook (Graph)</td><td><span class="chip muted">Planned — not implemented</span></td></tr>
      <tr><td>Continuous inbox protection</td><td><span class="chip muted">Not offered</span></td></tr>
    </tbody></table></div>
  </section>
  <section class="card" aria-labelledby="st-del"><h2 id="st-del">Delete data</h2><p class="small muted">Removes saved history, settings, the current analysis and any session key from this browser.</p><button class="btn danger" id="delete-all" type="button">Delete all Shield data in this browser</button></section>
  <section class="card" id="privacy" aria-labelledby="st-priv"><h2 id="st-priv">Privacy summary</h2><ul class="feature-list small">
    <li>The scanner parses messages in your browser. Message content is not uploaded.</li>
    <li>Reputation checks send only the selected URLs, and only after you consent.</li>
    <li>AI analysis sends the message text to the model provider, and only after you consent.</li>
    <li>The server logs operational metadata (counts, latency, token usage) — never message text or URLs.</li>
    <li>No analytics, advertising trackers or third-party fonts are loaded.</li>
    <li>Use synthetic or your own messages. Do not submit other people's private email unless you are authorized.</li></ul></section>
</div>` });

const check = process.argv.includes("--check");
let stale = 0;
for (const p of PAGES) {
  const html = shell(p);
  if (check) { if (!existsSync(p.file) || readFileSync(p.file, "utf8") !== html) { console.error("Out of date: " + p.file); stale++; } continue; }
  mkdirSync(dirname(p.file), { recursive: true });
  writeFileSync(p.file, html);
  console.log("wrote " + p.file);
}
if (check) { if (stale) { console.error("Run: node scripts/pages.mjs"); process.exit(1); } console.log("Generated pages are up to date."); }
export { PAGES, SHIELD_NAV, RESEARCH_NAV };
