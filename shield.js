// PhishExplain Shield — browser entry point. Loads the module for the current page.
const PAGES = {
  home: () => import("./shield/ui/pages/home.js"),
  scanner: () => import("./shield/ui/pages/scanner.js"),
  dashboard: () => import("./shield/ui/pages/dashboard.js"),
  links: () => import("./shield/ui/pages/links.js"),
  headers: () => import("./shield/ui/pages/headers.js"),
  analysis: () => import("./shield/ui/pages/analysis.js"),
  reports: () => import("./shield/ui/pages/reports.js"),
  settings: () => import("./shield/ui/pages/settings.js")
};

function setupMenu() {
  const btn = document.getElementById("menu-btn"), nav = document.getElementById("site-nav");
  if (!btn || !nav) return;
  const close = () => { nav.classList.remove("open"); btn.setAttribute("aria-expanded", "false"); };
  btn.addEventListener("click", () => { const open = nav.classList.toggle("open"); btn.setAttribute("aria-expanded", String(open)); if (open) nav.querySelector("a")?.focus(); });
  document.addEventListener("keydown", e => { if (e.key === "Escape" && nav.classList.contains("open")) { close(); btn.focus(); } });
}

async function start() {
  setupMenu();
  const load = PAGES[document.body.dataset.page];
  if (!load) return;
  try { (await load()).init(); document.body.dataset.ready = "true"; }
  catch (err) {
    const main = document.getElementById("main");
    const box = document.createElement("div");
    box.className = "wrap alert error";
    box.setAttribute("role", "alert");
    box.textContent = "This page failed to load: " + (err?.message || "unknown error") + ". Please reload.";
    main?.prepend(box);
    console.error(err);
  }
}
start();
