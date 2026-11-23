import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { join } from "node:path";

const SHIELD = ["index.html", "security/index.html", "security/dashboard/index.html", "security/links/index.html", "security/headers/index.html", "security/analysis/index.html", "security/reports/index.html", "security/settings/index.html"];
const RESEARCH = ["lab", "dataset", "annotation", "evaluation", "errors", "research", "methods", "course", "presentation", "nlp"].map(r => r + "/index.html");

function resolveLocal(href) {
  const path = href.split(/[?#]/)[0];
  if (!path || !path.startsWith("/")) return true;
  const p = "." + decodeURIComponent(path);
  if (existsSync(p) && statSync(p).isFile()) return true;
  if (existsSync(join(p, "index.html"))) return true;
  if (existsSync(p + ".html")) return true;
  return false;
}

test("all required product and research routes exist", () => {
  for (const f of [...SHIELD, ...RESEARCH]) assert.ok(existsSync(f) && statSync(f).size > 500, f);
});

test("Shield pages load existing assets and use one navigation with both areas", () => {
  assert.ok(existsSync("shield.js") && existsSync("shield.css"));
  for (const f of SHIELD) {
    const t = readFileSync(f, "utf8");
    assert.match(t, /<script type="module" src="\/shield.js"><\/script>/, f);
    assert.match(t, /<link rel="stylesheet" href="\/shield.css">/, f);
    assert.match(t, /<main id="main"/, f);
    assert.match(t, /class="skip" href="#main"/, f);
    assert.match(t, /nav-label">Shield</, f);
    assert.match(t, /nav-label">Research Lab</, f);
    assert.match(t, /data-page="[a-z]+"/, f);
  }
});

test("Shield pages are compatible with the strict CSP (no inline script, style or handlers)", () => {
  for (const f of SHIELD) {
    const t = readFileSync(f, "utf8");
    assert.doesNotMatch(t, /\sstyle="/, f);
    assert.doesNotMatch(t, /<script(?![^>]*\bsrc=)[^>]*>/, f);
    assert.doesNotMatch(t, /\son[a-z]+="/, f);
    assert.doesNotMatch(t, /fonts\.googleapis|https?:\/\/(?!github\.com|reportfraud\.ftc\.gov)[a-z0-9.-]+\/[^"]*\.(js|css)/, f);
  }
});

test("every internal link and asset reference resolves to a file", () => {
  for (const f of [...SHIELD, ...RESEARCH]) {
    const t = readFileSync(f, "utf8");
    for (const m of t.matchAll(/\s(?:href|src)="(\/[^"]*)"/g)) assert.ok(resolveLocal(m[1]), `${f} → ${m[1]}`);
  }
});

test("every page module referenced by shield.js exists and exports init", async () => {
  const src = readFileSync("shield.js", "utf8");
  const mods = [...src.matchAll(/import\("\.\/(shield\/ui\/pages\/[a-z]+\.js)"\)/g)].map(m => m[1]);
  assert.equal(mods.length, 8);
  for (const m of mods) { assert.ok(existsSync(m), m); assert.match(readFileSync(m, "utf8"), /export function init\(/, m); }
});

test("UI code never writes email content through innerHTML", () => {
  const dir = "shield/ui";
  const files = readdirSync(dir, { recursive: true }).filter(f => String(f).endsWith(".js"));
  const code = f => readFileSync(join(dir, String(f)), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  for (const f of files) assert.doesNotMatch(code(f), /innerHTML|outerHTML|insertAdjacentHTML|document\.write/, String(f));
});

test("vercel.json applies a strict CSP to Shield pages and no-store to APIs", () => {
  const v = JSON.parse(readFileSync("vercel.json", "utf8"));
  const csp = src => v.headers.find(h => h.source === src)?.headers.find(x => x.key === "Content-Security-Policy")?.value || "";
  for (const s of ["/", "/security/(.*)"]) { assert.match(csp(s), /script-src 'self';/); assert.match(csp(s), /style-src 'self';/); assert.match(csp(s), /frame-ancestors 'none'/); assert.doesNotMatch(csp(s), /unsafe/); }
  assert.ok(v.headers.find(h => h.source === "/api/(.*)").headers.some(x => x.key === "Cache-Control" && x.value === "no-store"));
  assert.equal(v.cleanUrls, true);
});

test("vendored libraries match the manifest", async () => {
  const { createHash } = await import("node:crypto");
  const m = JSON.parse(readFileSync("vendor/manifest.json", "utf8"));
  for (const [name, lib] of Object.entries(m.libraries)) assert.equal(createHash("sha256").update(readFileSync(lib.file, "utf8")).digest("hex"), lib.sha256, name);
});
