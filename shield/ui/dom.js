// Minimal DOM helpers. Email-derived content is only ever inserted as text nodes / textContent,
// never through innerHTML, so message HTML and scripts cannot execute.
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/**
 * h("div", {class:"x", text:"y", attrs:{...}, on:{click}}, ...children)
 * Strings become text nodes. null/false children are skipped.
 */
export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = String(v);
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else if (k === "attrs") for (const [a, av] of Object.entries(v)) { if (av !== null && av !== undefined && av !== false) el.setAttribute(a, av === true ? "" : String(av)); }
    else if (k === "hidden") el.hidden = Boolean(v);
    else if (k === "href") { const safe = safeHref(v); if (safe) el.setAttribute("href", safe); }
    else el[k] = v;
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}
/** Only same-site paths and https links to known documentation are allowed as live hrefs. */
export function safeHref(v) {
  const s = String(v);
  if (s.startsWith("/") && !s.startsWith("//")) return s;
  if (/^https:\/\/(www\.virustotal\.com|urlhaus\.abuse\.ch|transparencyreport\.google\.com|github\.com\/Arungharami)\//.test(s)) return s;
  return null;
}

const SVG_NS = "http://www.w3.org/2000/svg";
export function svg(tag, attrs = {}, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  for (const c of children) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}

export function setStatus(el, message, kind = "") {
  if (!el) return;
  el.textContent = message || "";
  el.className = "small" + (kind ? " status-" + kind : "");
  if (kind === "error") el.setAttribute("role", "alert"); else el.setAttribute("role", "status");
}

export function download(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = h("a", { attrs: { download: filename } });
  a.href = url;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function chip(text, kind = "") { return h("span", { class: "chip" + (kind ? " " + kind : ""), text }); }
export function fmtDate(iso) { try { return new Date(iso).toLocaleString(); } catch { return String(iso); } }
export function fmtBytes(n) { if (!Number.isFinite(n)) return "—"; if (n < 1024) return n + " B"; if (n < 1048576) return (n / 1024).toFixed(1) + " KB"; return (n / 1048576).toFixed(2) + " MB"; }
