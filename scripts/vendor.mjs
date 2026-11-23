#!/usr/bin/env node
// Re-generates browser-ready single-file ESM copies of third-party libraries in /vendor.
// The browser cannot resolve bare npm specifiers without a bundler, so we bundle once,
// commit the output, and record exact versions + SHA-256 hashes in vendor/manifest.json.
// Usage: npm run vendor            (rebuild)
//        node scripts/vendor.mjs --check   (fail if vendored files drift from node_modules)
import { build } from "esbuild";
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";

const LIBS = [
  { name: "postal-mime", entry: "node_modules/postal-mime/dist/esm/postal-mime.js", out: "vendor/postal-mime.js", license: "node_modules/postal-mime/LICENSE.txt" },
  { name: "tldts", entry: "node_modules/tldts/dist/index.esm.min.js", out: "vendor/tldts.js", license: "node_modules/tldts/LICENSE" }
];
const sha = buf => createHash("sha256").update(buf).digest("hex");
const check = process.argv.includes("--check");
mkdirSync("vendor", { recursive: true });
const manifest = { generated_by: "scripts/vendor.mjs", libraries: {} };
let drift = false;
for (const lib of LIBS) {
  const pkg = JSON.parse(readFileSync(`node_modules/${lib.name}/package.json`, "utf8"));
  const result = await build({ entryPoints: [lib.entry], bundle: true, format: "esm", platform: "neutral", minify: false, write: false, legalComments: "inline", target: "es2020" });
  const code = `/* ${lib.name}@${pkg.version} (${pkg.license}) — vendored by scripts/vendor.mjs. Do not edit. */\n` + result.outputFiles[0].text;
  if (check) {
    if (!existsSync(lib.out) || readFileSync(lib.out, "utf8") !== code) { console.error(`Vendored ${lib.out} differs from node_modules/${lib.name}@${pkg.version}`); drift = true; }
  } else {
    writeFileSync(lib.out, code);
    if (existsSync(lib.license)) copyFileSync(lib.license, `vendor/${lib.name}.LICENSE.txt`);
  }
  manifest.libraries[lib.name] = { version: pkg.version, license: pkg.license, file: lib.out, sha256: sha(code) };
}
if (check) { if (drift) process.exit(1); console.log("Vendored libraries match node_modules."); }
else { writeFileSync("vendor/manifest.json", JSON.stringify(manifest, null, 2) + "\n"); console.log(JSON.stringify(manifest, null, 2)); }
