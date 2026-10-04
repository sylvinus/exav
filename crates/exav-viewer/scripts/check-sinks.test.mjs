// The source check must catch each sink planted in otherwise clean code, and
// pass the package as it is.
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { ALLOWED, checkSinks, findSinks, sources } from "./check-sinks.mjs";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const PLANTED = [
  ["eval", "eval(code);"],
  ["eval", "window.eval(code);"],
  ["Function constructor", 'new Function("a", body);'],
  ["Function constructor", "Function(body)();"],
  ["string timer", 'setTimeout("run()", 10);'],
  ["string timer", "setInterval(`tick(${n})`, 10);"],
  ["string timer", 'window.setTimeout("a" + b, 1);'],
  ["innerHTML", "el.innerHTML = html;"],
  ["innerHTML", "el.innerHTML += more;"],
  ["outerHTML", "el.outerHTML = html;"],
  ["srcdoc", "frame.srcdoc = html;"],
  ["insertAdjacentHTML", 'el.insertAdjacentHTML("beforeend", html);'],
  ["document.write", "document.write(html);"],
  ["document.write", "document.writeln(html);"],
  ["createContextualFragment", "range.createContextualFragment(html);"],
  ["parseFromString", 'new DOMParser().parseFromString(html, "text/html");'],
  ["window.open", "window.open(url);"],
  ["window.open", "open(url);"],
  ["window.open", "globalThis.open(url);"],
  ["postMessage to *", 'parent.postMessage(data, "*");'],
  ["event handler attribute", 'el.setAttribute("onclick", code);'],
  ["event handler attribute", 'el.setAttribute("ONLOAD", "x()");'],
  ["href from a variable", 'a.setAttribute("href", url);'],
  ["src from a variable", 'img.setAttribute("src", url);'],
  ["href from a variable", "a.href = url;"],
  ["src from a variable", "script.src = url;"],
  ["event handler from a string", 'el.onclick = "alert(1)";'],
  ["javascript: URL", 'const u = "javascript:void(0)";'],
  ["javascript: URL", "const u = `JavaScript :${x}`;"],
  ["importScripts", "importScripts(url);"],
  ["import() of a variable", "await import(url);"],
  ["worker from a variable", "new Worker(url);"],
  ["worker from a variable", 'new Worker(new URL(name, import.meta.url), { type: "module" });'],
];

describe("the source check", () => {
  for (const [rule, code] of PLANTED) {
    it(`finds ${rule} in \`${code}\``, () => {
      const found = findSinks([{ path: "ts/x.ts", text: `export function f(el: any, url: string) {\n  ${code}\n}\n` }]);
      expect(found.map((s) => s.rule)).toEqual([rule]);
    });
  }

  it("finds dangerouslySetInnerHTML in JSX", () => {
    const found = findSinks([{ path: "ts/x.tsx", text: "export const X = ({ h }: { h: string }) => <div dangerouslySetInnerHTML={{ __html: h }} />;\n" }]);
    expect(found.map((s) => s.rule)).toEqual(["dangerouslySetInnerHTML"]);
  });

  it("leaves alone what is not a sink", () => {
    const clean = [
      "// el.innerHTML = x; eval(x); window.open(x)",
      'el.textContent = text; img.src = ""; a.setAttribute("title", name);',
      'new Worker(new URL("./x.worker.js", import.meta.url), { type: "module" });',
      'setTimeout(() => run(), 10); await import("./engine.js");',
      'archive.open(index); port.postMessage(message); a.setAttribute("href", "#top");',
      "const text = 'innerHTML';",
    ].join("\n");
    expect(findSinks([{ path: "ts/x.ts", text: clean }])).toEqual([]);
  });

  it("refuses a planted sink in a file of the package, and an allowed entry that no longer matches", () => {
    const files = sources(root);
    expect(checkSinks(files)).toEqual({ refused: [], stale: [] });
    const planted = files.map((f) => (f.path === "ts/core/viewer.ts" ? { ...f, text: `${f.text}\nexport const x = (h: string, e: HTMLElement) => (e.innerHTML = h);\n` } : f));
    expect(checkSinks(planted).refused.map((s) => `${s.file} ${s.rule}`)).toEqual(["ts/core/viewer.ts innerHTML"]);
    const withoutOne = files.filter((f) => f.path !== ALLOWED[0].file);
    expect(checkSinks(withoutOne).stale.length).toBeGreaterThan(0);
  });
});
