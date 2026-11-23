// Email input parsing. Uses postal-mime (vendored) for RFC 5322 / MIME handling.
// Attachment bytes are inspected ONLY for size and the first few "magic" bytes; they are never
// executed, rendered, decompressed or uploaded. HTML parts are kept as inert strings.
import PostalMime from "../../vendor/postal-mime.js";
import { htmlToText } from "./text.js";

export const LIMITS = Object.freeze({
  maxInputBytes: 5 * 1024 * 1024,   // whole .eml / paste
  maxAnalyzedTextChars: 200000,      // language + URL scan window per part
  maxAttachments: 50,
  maxHeaders: 500
});

const HEADER_LINE = /^[\x21-\x39\x3b-\x7e]{1,76}:[ \t]?/;
const KNOWN_HEADERS = /^(from|to|cc|reply-to|return-path|subject|date|received|message-id|mime-version|content-type|authentication-results|arc-[a-z-]+|dkim-signature|received-spf|delivered-to|sender|x-[a-z0-9-]+):/i;

/** Decide whether pasted text starts with an RFC 5322 header block. */
export function looksLikeRawMessage(text) {
  const lines = String(text).replace(/\r\n?/g, "\n").split("\n");
  let known = 0, total = 0;
  for (const line of lines.slice(0, 400)) {
    if (line === "") break;
    if (/^[ \t]/.test(line) && total > 0) continue; // folded continuation
    if (!HEADER_LINE.test(line)) return false;
    total++;
    if (KNOWN_HEADERS.test(line)) known++;
  }
  return total > 0 && known > 0;
}

const SIGNATURES = [
  { type: "windows-executable", ext: ["exe", "dll", "scr", "com", "cpl", "sys"], bytes: [0x4d, 0x5a] },
  { type: "elf-executable", ext: [], bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { type: "pdf", ext: ["pdf"], bytes: [0x25, 0x50, 0x44, 0x46] },
  { type: "zip-container", ext: ["zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar", "apk", "odt", "ods", "odp", "epub", "xlam", "dotm", "msix", "appx", "vsix", "kmz"], bytes: [0x50, 0x4b, 0x03, 0x04] },
  { type: "ole-compound", ext: ["doc", "xls", "ppt", "msi", "msg", "xlsb", "dot", "pub", "vsd"], bytes: [0xd0, 0xcf, 0x11, 0xe0] },
  { type: "rar", ext: ["rar"], bytes: [0x52, 0x61, 0x72, 0x21] },
  { type: "7z", ext: ["7z"], bytes: [0x37, 0x7a, 0xbc, 0xaf] },
  { type: "gzip", ext: ["gz", "tgz"], bytes: [0x1f, 0x8b] },
  { type: "png", ext: ["png"], bytes: [0x89, 0x50, 0x4e, 0x47] },
  { type: "jpeg", ext: ["jpg", "jpeg"], bytes: [0xff, 0xd8, 0xff] },
  { type: "gif", ext: ["gif"], bytes: [0x47, 0x49, 0x46, 0x38] },
  { type: "rtf", ext: ["rtf", "doc"], bytes: [0x7b, 0x5c, 0x72, 0x74, 0x66] },
  { type: "iso9660", ext: ["iso", "img"], bytes: null }
];
function sniff(bytes) {
  if (!bytes || !bytes.length) return null;
  for (const s of SIGNATURES) if (s.bytes && s.bytes.every((b, i) => bytes[i] === b)) return s;
  return null;
}
const toHex = bytes => Array.from(bytes.slice(0, 8), b => b.toString(16).padStart(2, "0")).join(" ");

function asBytes(content) {
  if (!content) return new Uint8Array(0);
  if (content instanceof Uint8Array) return content;
  if (content instanceof ArrayBuffer) return new Uint8Array(content);
  if (typeof content === "string") return new TextEncoder().encode(content);
  return new Uint8Array(0);
}

/**
 * Parse supplied input into a normalized message model.
 * @param {string|ArrayBuffer|Uint8Array} input
 * @param {{source?: "paste"|"eml_file"|"txt_file", fileName?: string}} opts
 */
export async function parseMessage(input, opts = {}) {
  const warnings = [];
  const source = opts.source || "paste";
  let size = 0, rawText = null;
  if (typeof input === "string") { rawText = input; size = new TextEncoder().encode(input).length; }
  else if (input instanceof ArrayBuffer || input instanceof Uint8Array) { size = input.byteLength; }
  else throw new TypeError("Unsupported input type");
  if (size === 0 || (rawText !== null && !rawText.trim())) throw new Error("Provide email text or a file to analyze.");
  if (size > LIMITS.maxInputBytes) throw new RangeError(`Input is ${(size / 1048576).toFixed(1)} MB; the local analysis limit is ${LIMITS.maxInputBytes / 1048576} MB.`);

  const decodedForDetection = rawText ?? new TextDecoder("utf-8", { fatal: false }).decode(asBytes(input).slice(0, 65536));
  const isRaw = source === "eml_file" ? true : looksLikeRawMessage(decodedForDetection);

  const model = {
    input: { source, file_name: opts.fileName || null, size_bytes: size, kind: isRaw ? "raw_message" : "body_text", mime_parsed: false, warnings },
    headers: [], from: null, from_raw: null, sender: null, reply_to: [], return_path: null, to: [], cc: [], subject: null, date: null, message_id: null,
    text: "", html: "", html_text: "", attachments: []
  };

  if (!isRaw) {
    const body = rawText ?? decodedForDetection;
    if (/<\s*(a|html|body|div|table|form|p)\b[^>]*>/i.test(body)) { model.html = body; model.html_text = htmlToText(body); warnings.push("Input contains HTML markup; it was analyzed as inert text and never rendered."); }
    model.text = body;
    if (source === "eml_file") warnings.push("No header block found in the file.");
    return model;
  }

  let email;
  try {
    email = await PostalMime.parse(input, { attachmentEncoding: "arraybuffer", maxNestingDepth: 50, maxHeadersSize: 2 * 1024 * 1024 });
    model.input.mime_parsed = true;
  } catch (err) {
    warnings.push("MIME parsing failed (" + (err?.message || "malformed message") + "); analyzed as plain text instead.");
    const body = rawText ?? decodedForDetection;
    model.input.kind = "body_text";
    model.text = body;
    return model;
  }

  model.headers = (email.headers || []).slice(0, LIMITS.maxHeaders).map(h => ({ key: h.key, name: h.originalKey || h.key, value: String(h.value ?? "") }));
  if ((email.headers || []).length > LIMITS.maxHeaders) warnings.push(`Only the first ${LIMITS.maxHeaders} headers were analyzed.`);
  const fromHeaders = model.headers.filter(h => h.key === "from");
  model.from_raw = fromHeaders.map(h => h.value);
  model.from = email.from ? { name: email.from.name || "", address: (email.from.address || "").toLowerCase() } : null;
  model.sender = email.sender ? { name: email.sender.name || "", address: (email.sender.address || "").toLowerCase() } : null;
  model.reply_to = (email.replyTo || []).map(a => ({ name: a.name || "", address: (a.address || "").toLowerCase() })).filter(a => a.address);
  model.return_path = email.returnPath ? String(email.returnPath).toLowerCase() : null;
  model.to = (email.to || []).map(a => ({ name: a.name || "", address: (a.address || "").toLowerCase() }));
  model.cc = (email.cc || []).map(a => ({ name: a.name || "", address: (a.address || "").toLowerCase() }));
  model.subject = email.subject ?? null;
  model.date = email.date ?? null;
  model.message_id = email.messageId ?? null;
  model.text = String(email.text ?? "");
  model.html = String(email.html ?? "");
  if (model.html) model.html_text = htmlToText(model.html);
  if (!model.headers.length) warnings.push("No headers were recognized.");
  if (!model.text && !model.html && !(email.attachments || []).length) warnings.push("The message has no readable body.");

  const atts = email.attachments || [];
  if (atts.length > LIMITS.maxAttachments) warnings.push(`Only the first ${LIMITS.maxAttachments} attachments were inspected.`);
  model.attachments = atts.slice(0, LIMITS.maxAttachments).map((a, i) => {
    const bytes = asBytes(a.content);
    const sig = sniff(bytes);
    return {
      index: i,
      filename: a.filename || null,
      mime_type: a.mimeType || null,
      disposition: a.disposition || null,
      content_id: a.contentId || null,
      inline: a.disposition === "inline" || Boolean(a.related),
      size_bytes: bytes.length,
      leading_bytes_hex: bytes.length ? toHex(bytes) : null,
      detected_signature: sig ? sig.type : null,
      signature_extensions: sig ? sig.ext : null
    };
  });
  return model;
}
