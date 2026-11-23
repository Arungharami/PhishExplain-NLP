// Attachment METADATA inspection. No malware scanning, sandboxing, decompression or execution occurs.
import { makeFinding } from "./rules.js";
import { truncate } from "./text.js";

export const EXECUTABLE_EXT = new Set(["exe", "scr", "com", "bat", "cmd", "pif", "cpl", "msi", "msp", "mst", "js", "jse", "vbs", "vbe", "wsf", "wsh", "ws", "ps1", "psm1", "lnk", "hta", "jar", "reg", "inf", "scf", "chm", "gadget", "application", "appref-ms", "url", "settingcontent-ms", "xll", "one", "onepkg", "msc", "dll", "sys", "appx", "msix", "appxbundle", "msixbundle", "library-ms", "search-ms", "iqy", "slk", "sh", "command", "app", "dmg", "pkg", "apk"]);
export const MACRO_EXT = new Set(["docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm", "xlsb"]);
export const ARCHIVE_EXT = new Set(["zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "ace", "arj", "lzh", "z", "iso", "img", "vhd", "vhdx", "udf"]);
export const HTML_EXT = new Set(["html", "htm", "shtml", "xhtml", "mht", "mhtml", "svg", "svgz"]);
const DOC_LIKE = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "csv", "odt", "mp3", "mp4", "wav", "zip"]);
const BIDI = /[‪-‮⁦-⁩‎‏]/;
const EXT_MIME = { pdf: /pdf/, docx: /word|officedocument|octet/, xlsx: /sheet|excel|officedocument|octet/, pptx: /presentation|powerpoint|officedocument|octet/, jpg: /jpe?g|image|octet/, jpeg: /jpe?g|image|octet/, png: /png|image|octet/, gif: /gif|image|octet/, txt: /text|octet/, csv: /csv|text|excel|octet/, zip: /zip|compressed|octet/, html: /html|text|octet/, htm: /html|text|octet/ };

export function extensionsOf(filename) {
  const base = String(filename || "").replace(BIDI, "").trim().toLowerCase();
  const parts = base.split(".");
  if (parts.length < 2) return [];
  return parts.slice(1).map(p => p.trim()).filter(p => /^[a-z0-9-]{1,20}$/.test(p));
}

export function analyzeAttachments(attachments) {
  const findings = [];
  const records = [];
  for (const a of attachments || []) {
    const name = a.filename || "(unnamed)";
    const exts = extensionsOf(a.filename);
    const last = exts.at(-1) || null;
    const rec = { ...a, extension: last, all_extensions: exts, malware_scanned: false, flags: [] };
    const src = "attachment:" + truncate(name, 80);
    const push = (rule, evidence, extra = {}) => { findings.push(makeFinding(rule, { evidence, source: src, details: { filename: name, mime_type: a.mime_type, size_bytes: a.size_bytes }, ...extra })); rec.flags.push(rule); };

    if (a.filename && BIDI.test(a.filename)) push("attach.rtlo", `File name contains invisible bidirectional control characters; real extension is ".${last}"`);
    if (exts.length >= 2 && DOC_LIKE.has(exts.at(-2)) && (EXECUTABLE_EXT.has(last) || HTML_EXT.has(last))) push("attach.double-extension", `"${truncate(name, 80)}" ends in .${exts.at(-2)}.${last}`);
    else if (/\s{3,}\.[a-z0-9]+$/i.test(String(a.filename || "")) && EXECUTABLE_EXT.has(last)) push("attach.double-extension", `"${truncate(name, 80)}" pads spaces before .${last}`);
    else if (last && EXECUTABLE_EXT.has(last)) push("attach.executable", `.${last} file: ${truncate(name, 80)}`);
    if (last && MACRO_EXT.has(last)) push("attach.macro", `.${last} file: ${truncate(name, 80)}`);
    if (last && HTML_EXT.has(last)) push("attach.html", `.${last} file: ${truncate(name, 80)}`);
    if (last && ARCHIVE_EXT.has(last)) push("attach.archive", `.${last} file: ${truncate(name, 80)}`);
    if (a.detected_signature && last && a.signature_extensions && !a.signature_extensions.includes(last)) {
      const dangerous = a.detected_signature === "windows-executable" || a.detected_signature === "elf-executable";
      if (dangerous || !(a.detected_signature === "zip-container" && ARCHIVE_EXT.has(last))) push("attach.type-mismatch", `Named .${last} but content begins like ${a.detected_signature} (bytes ${a.leading_bytes_hex})`, dangerous ? {} : { priority: "medium", points: 12 });
    }
    if (last && a.mime_type && EXT_MIME[last] && !EXT_MIME[last].test(a.mime_type.toLowerCase())) push("attach.mime-mismatch", `.${last} declared as ${a.mime_type}`);
    records.push(rec);
  }
  return { attachments: records, findings };
}
