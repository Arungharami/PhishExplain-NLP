import { extractSignals, SAMPLES, ENGINE_MAX_LENGTH } from "./engine.js";

const $ = selector => document.querySelector(selector);
const input = $("#message-input");
const chars = $("#char-count");
const status = $("#result-status");
const signals = $("#signals-panel");
const jsonPanel = $("#json-panel");
const jsonContent = $("#json-content");
const exportButton = $("#download-json");
const navToggle = $("#menu-toggle");
const mobileNav = $("#mobile-nav");
let lastResult = null;
let currentSample = "account";

function setInput(text) {
  input.value = text;
  chars.textContent = text.length.toLocaleString() + " / " + ENGINE_MAX_LENGTH.toLocaleString() + " characters";
  chars.style.color = text.length > ENGINE_MAX_LENGTH ? "#f39b8e" : "";
  status.textContent = "Awaiting analysis";
  status.classList.remove("complete");
  lastResult = null;
  exportButton.disabled = true;
  signals.replaceChildren(makeEmpty());
  jsonContent.textContent = '{ "status": "awaiting_analysis" }';
}

function makeElement(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}

function makeEmpty() {
  const el = makeElement("div", "empty-results");
  el.append(makeElement("div", "empty-orbit", "◎"));
  el.append(makeElement("strong", "", "No extraction yet"));
  el.append(makeElement("p", "", "Select a sample and run the baseline to inspect matched text spans and rule explanations."));
  return el;
}

function showSignals(result) {
  const shell = makeElement("div", "result-container");
  const summary = makeElement("div", "result-summary");
  const intro = makeElement("div");
  intro.append(makeElement("strong", "", result.total_matches === 0 ? "No lexical cues found" : "Potential language cues extracted"));
  intro.append(makeElement("p", "", "Rule matches • Original text offsets • No risk verdict"));
  summary.append(intro, makeElement("div", "result-total", String(result.total_matches).padStart(2, "0")));
  shell.append(summary);

  const list = makeElement("div", "category-list");
  for (const group of result.categories) {
    const row = makeElement("div", "category-row " + group.key);
    const head = makeElement("div", "category-head");
    head.append(makeElement("span", "category-name", group.title));
    head.append(makeElement("span", "category-count", group.matches.length + " matches"));
    row.append(head);
    const chips = makeElement("div", "category-hits");
    if (!group.matches.length) {
      chips.append(makeElement("span", "no-match", "No matching rule evidence"));
    } else {
      for (const match of group.matches) {
        const chip = makeElement("span", "hit-chip", match.text);
        chip.title = "Character offset [" + match.start + ", " + match.end + ") · " + match.rule;
        chips.append(chip);
      }
    }
    row.append(chips);
    list.append(row);
  }
  shell.append(list, makeElement("p", "result-disclaimer", "Interpretation limit: words can occur in legitimate warnings, quotations, or negated instructions. A matched URL is not inherently unsafe. Review all evidence in context."));
  signals.replaceChildren(shell);
}

function analyze() {
  const value = input.value;
  if (!value.trim()) {
    status.textContent = "Enter an email first";
    input.focus();
    return;
  }
  try {
    const result = extractSignals(value);
    lastResult = result;
    status.textContent = "Baseline completed";
    status.classList.add("complete");
    showSignals(result);
    jsonContent.textContent = JSON.stringify(result, null, 2);
    exportButton.disabled = false;
  } catch (error) {
    status.textContent = error.message;
    status.classList.remove("complete");
    lastResult = null;
    exportButton.disabled = true;
  }
}

function setView(view) {
  const isJson = view === "json";
  signals.hidden = isJson;
  jsonPanel.hidden = !isJson;
  $("#view-signals").classList.toggle("active", !isJson);
  $("#view-json").classList.toggle("active", isJson);
  $("#view-signals").setAttribute("aria-pressed", String(!isJson));
  $("#view-json").setAttribute("aria-pressed", String(isJson));
}

async function copyResult() {
  if (!lastResult) return;
  const text = JSON.stringify(lastResult, null, 2);
  try {
    await navigator.clipboard.writeText(text);
    const button = $("#copy-json");
    button.textContent = "Copied ✓";
    button.blur();
    window.setTimeout(() => button.textContent = "Copy JSON ↗", 1600);
  } catch {
    const pre = $("#json-content");
    const range = document.createRange();
    range.selectNodeContents(pre);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    $("#copy-json").textContent = "Select text to copy";
  }
}

function downloadResult() {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
  const uri = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = uri;
  link.download = "phishexplain-local-baseline.json";
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(uri), 250);
}

document.querySelectorAll("[data-sample]").forEach(button => {
  button.addEventListener("click", () => {
    currentSample = button.dataset.sample;
    document.querySelectorAll("[data-sample]").forEach(b => b.classList.toggle("active", b === button));
    setInput(SAMPLES[currentSample].text);
  });
});
input.addEventListener("input", () => {
  chars.textContent = input.value.length.toLocaleString() + " / " + ENGINE_MAX_LENGTH.toLocaleString() + " characters";
  chars.style.color = input.value.length > ENGINE_MAX_LENGTH ? "#f39b8e" : "";
  if (lastResult) {
    lastResult = null;
    status.textContent = "Input changed — run extraction again";
    status.classList.remove("complete");
    exportButton.disabled = true;
    signals.replaceChildren(makeEmpty());
    jsonContent.textContent = '{ "status": "awaiting_analysis" }';
  }
});
$("#clear-input").addEventListener("click", () => {
  setInput("");
  document.querySelectorAll("[data-sample]").forEach(b => b.classList.remove("active"));
  input.focus();
});
$("#analyze-button").addEventListener("click", analyze);
$("#view-signals").addEventListener("click", () => setView("signals"));
$("#view-json").addEventListener("click", () => setView("json"));
$("#copy-json").addEventListener("click", copyResult);
exportButton.addEventListener("click", downloadResult);
navToggle.addEventListener("click", () => {
  const open = mobileNav.hidden;
  mobileNav.hidden = !open;
  navToggle.setAttribute("aria-expanded", String(open));
  navToggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
});
mobileNav.querySelectorAll("a").forEach(link => link.addEventListener("click", () => {
  mobileNav.hidden = true;
  navToggle.setAttribute("aria-expanded", "false");
  navToggle.setAttribute("aria-label", "Open navigation");
}));
setInput(SAMPLES.account.text);
