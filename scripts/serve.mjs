#!/usr/bin/env node
// Local development server that mirrors the Vercel deployment closely enough for testing:
// static files with cleanUrls, the headers from vercel.json, and /api/* Node functions.
// Usage: node scripts/serve.mjs [port]   (default 4173). Reads environment variables from the shell only.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { extname, join, normalize, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = resolve(".");
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml", ".csv": "text/csv; charset=utf-8", ".md": "text/markdown; charset=utf-8", ".txt": "text/plain; charset=utf-8", ".png": "image/png" };
const BLOCKED = /^\/(node_modules|\.git|\.env|\.vercel|tests|scripts)(\/|$)/;
const vercel = JSON.parse(readFileSync("vercel.json", "utf8"));

function headersFor(pathname) {
  const out = {};
  for (const rule of vercel.headers || []) {
    const re = new RegExp("^" + rule.source.replace(/\(\.\*\)/g, ".*").replace(/:path\*/g, ".*") + "$");
    if (re.test(pathname)) for (const hd of rule.headers) out[hd.key] = hd.value;
  }
  return out;
}

async function apiHandler(req, res, pathname) {
  const name = pathname.replace(/^\/api\//, "").replace(/\/$/, "");
  if (!/^[a-z0-9-]+$/.test(name)) { res.writeHead(404).end(); return; }
  let mod;
  try { mod = await import(pathToFileURL(join(ROOT, "api", name + ".js")).href); } catch { res.writeHead(404, { "Content-Type": "application/json" }).end('{"error":"Not found"}'); return; }
  const chunks = []; let size = 0;
  for await (const c of req) { size += c.length; if (size > 1_000_000) { res.writeHead(413).end(); return; } chunks.push(c); }
  const raw = Buffer.concat(chunks).toString("utf8");
  let body = raw;
  if (String(req.headers["content-type"] || "").startsWith("application/json") && raw) { try { body = JSON.parse(raw); } catch { body = raw; } }
  const vreq = { method: req.method, headers: req.headers, body, socket: req.socket };
  const vres = {
    statusCode: 200, _h: {},
    setHeader(k, v) { this._h[k] = v; return this; },
    status(n) { this.statusCode = n; return this; },
    json(obj) { res.writeHead(this.statusCode, { ...headersFor(pathname), ...this._h }); res.end(JSON.stringify(obj)); return this; }
  };
  await mod.default(vreq, vres);
}

export function startServer(port = 4173) {
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://localhost");
      let pathname = decodeURIComponent(url.pathname);
      if (pathname.startsWith("/api/")) return await apiHandler(req, res, pathname);
      if (BLOCKED.test(pathname) || pathname.includes("\0")) { res.writeHead(404).end("Not found"); return; }
      let file = normalize(join(ROOT, pathname));
      if (!file.startsWith(ROOT)) { res.writeHead(403).end(); return; }
      let st = await stat(file).catch(() => null);
      if (st?.isDirectory()) { file = join(file, "index.html"); st = await stat(file).catch(() => null); }
      if (!st && !extname(file)) { file += ".html"; st = await stat(file).catch(() => null); }
      if (!st) { res.writeHead(404, { "Content-Type": "text/plain" }).end("Not found"); return; }
      const body = await readFile(file);
      res.writeHead(200, { "Content-Type": TYPES[extname(file)] || "application/octet-stream", ...headersFor(pathname) });
      res.end(body);
    } catch (err) { res.writeHead(500).end("Server error"); console.error(err); }
  });
  return new Promise(r => server.listen(port, "127.0.0.1", () => r(server)));
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const port = Number(process.argv[2] || 4173);
  startServer(port).then(() => console.log(`PhishExplain dev server: http://127.0.0.1:${port}`));
}
