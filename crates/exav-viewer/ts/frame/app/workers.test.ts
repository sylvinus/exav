import vm from "node:vm";

import { describe, expect, it } from "vitest";

import { allowedHtml, workerBoot } from "./workers.js";

describe("the frame's default Trusted Types policy", () => {
  it("lets through the markup the engines write", () => {
    // The Office engine's validation arrow (its template, filled) and its clears.
    expect(allowedHtml('<svg width="12" height="12" viewBox="0 0 10 6" aria-hidden="true"><path d="M0 0 L10 0 L5 6 Z" fill="#333"/></svg>')).toBe(true);
    expect(allowedHtml("")).toBe(true);
  });

  it("refuses anything that can run code, load something, or carry text", () => {
    for (const html of [
      "<b>x</b>",
      "x",
      '<img src="x" onerror="alert(1)">',
      "<svg><script>alert(1)</script></svg>",
      '<svg onload="alert(1)"></svg>',
      '<svg><path d="M0 0" onclick="x"/></svg>',
      '<svg><a href="javascript:alert(1)"><path d="M0 0"/></a></svg>',
      '<svg><use href="https://x.test/#a"/></svg>',
      '<svg><image href="https://x.test/a.png"/></svg>',
      "<svg><foreignObject><iframe></iframe></foreignObject></svg>",
      '<svg><path style="background:url(https://x.test/)"/></svg>',
      '<svg><path d="&lt;script&gt;"/></svg>',
      "<svg><style>*{}</style></svg>",
      "<svg><path></svg>",
      "</svg>",
      '<svg viewBox="0 0 1 1">text</svg>',
      "<svg/><!-- -->",
    ]) {
      expect(allowedHtml(html), html).toBe(false);
    }
  });
});

describe("a worker's blob", () => {
  it("is a classic script that sets the script's URL and imports only it", () => {
    const calls: string[] = [];
    const self: Record<string, unknown> = { importScripts: (u: string) => calls.push(u) };
    vm.runInNewContext(workerBoot("https://frame.test/cad.worker.js"), { self, importScripts: self.importScripts });
    expect(self.EXAV_SCRIPT).toBe("https://frame.test/cad.worker.js");
    expect(calls).toEqual(["https://frame.test/cad.worker.js"]);
  });

  it("quotes the URL as data, whatever it holds", () => {
    const url = 'https://frame.test/a.js"); importScripts("https://x.test/evil.js'; // eslint-disable-line
    const calls: string[] = [];
    const self: Record<string, unknown> = {};
    vm.runInNewContext(workerBoot(url), { self, importScripts: (u: string) => calls.push(u) });
    expect(calls).toEqual([url]);
  });

  it("goes through a policy that accepts that URL alone, where Trusted Types exist", () => {
    const made: { name: string; accepts: (u: string) => unknown }[] = [];
    const trustedTypes = {
      createPolicy: (name: string, rules: { createScriptURL: (u: string) => string }) => {
        made.push({ name, accepts: (u) => rules.createScriptURL(u) });
        return { createScriptURL: (u: string) => ({ trusted: rules.createScriptURL(u) }) };
      },
    };
    const calls: unknown[] = [];
    vm.runInNewContext(workerBoot("https://frame.test/w.js"), { self: { trustedTypes }, importScripts: (u: unknown) => calls.push(u) });
    expect(made.map((p) => p.name)).toEqual(["exav-worker"]);
    expect(calls).toEqual([{ trusted: "https://frame.test/w.js" }]);
    // A TypeError of the script's own realm.
    expect(() => made[0]!.accepts("https://frame.test/other.js")).toThrow("not this worker's script");
  });
});
