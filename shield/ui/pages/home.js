import { EDUCATION } from "../../core/guidance.js";
import { $, h } from "../dom.js";
export function init() {
  $("#glossary")?.replaceChildren(...EDUCATION.map(e => h("div", {}, h("dt", { text: e.term }), h("dd", { text: e.text }))));
}
