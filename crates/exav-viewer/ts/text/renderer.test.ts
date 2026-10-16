import { describe, expect, it, vi } from "vitest";

import type { RenderContext, RendererHandle, Status } from "../core/types.js";
import "../test/blob.js";
import { MAX_BYTES, MAX_LINE, MAX_LINES } from "./decode.js";
import { kindOf, renderer } from "./renderer.js";

// The page reads Markdown in a worker, which jsdom has not: the same module, in this process.
const engine = vi.hoisted(() => ({ fail: false }));
vi.mock("./markdown-engine.js", async () => {
  const real = (await import("../test/markdown.js")).readMarkdown;
  return {
    readMarkdown: async (source: string) => {
      if (engine.fail) throw new Error("the engine stopped");
      return real(source);
    },
  };
});

const ch = (code: number) => String.fromCharCode(code);
const enc = (s: string) => new TextEncoder().encode(s);

interface Opened {
  host: HTMLElement;
  statuses: Status[];
  handle: RendererHandle;
  warnings: { key: string; count: number }[];
}

/** Mounts the renderer on a file as the viewer would. */
async function open(name: string, bytes: Uint8Array, type = ""): Promise<Opened> {
  const host = document.createElement("div");
  document.body.append(host);
  const statuses: Status[] = [];
  const blob = new Blob([bytes as BlobPart]);
  const ctx = {
    file: { id: "1", name, type, source: null },
    options: {},
    source: { blob: async () => blob, bytes: async () => bytes, url: async () => "", progress: { get: () => null, subscribe: () => () => {} } },
    signal: new AbortController().signal,
    assetBase: "",
    status: (s: Status) => statuses.push(s),
    controllers() {},
  } as unknown as RenderContext<Record<string, never>>;
  const handle = await renderer.mount(host, ctx);
  const warnings = handle.controllers.warnings?.get() ?? [];
  return { host, statuses, handle, warnings: [...warnings] };
}

/** Lets the chunks drawn after the first paint be drawn. */
async function settle(): Promise<void> {
  let seen = -1;
  for (let i = 0; i < 100; i++) {
    await new Promise((r) => setTimeout(r, 30));
    const now = document.querySelectorAll(".exav-viewer-text-chunk").length;
    if (now === seen) return;
    seen = now;
  }
}

/** The text on screen: each block is a line break apart, as a selection copied across them has it. */
function shownText(host: HTMLElement): string {
  const chunks = [...host.querySelectorAll(".exav-viewer-text-chunk")];
  return chunks.length ? chunks.map((c) => c.textContent).join("\n") : (host.querySelector(".exav-viewer-text")?.textContent ?? "");
}

describe("kindOf", () => {
  it("reads the name first, then the type, and shows anything else as plain text", () => {
    expect(kindOf("a/README.MD")).toBe("markdown");
    expect(kindOf("x.json")).toBe("json");
    expect(kindOf("x.kml")).toBe("xml");
    expect(kindOf("page.HTML")).toBe("html");
    expect(kindOf("fix.patch")).toBe("diff");
    expect(kindOf("main.rs")).toBe("plain");
    expect(kindOf("notes", "application/json; charset=utf-8")).toBe("json");
    expect(kindOf("notes", "text/markdown")).toBe("markdown");
    expect(kindOf("notes.txt", "application/json")).toBe("plain");
    expect(kindOf("notes")).toBe("plain");
  });
});

describe("the text renderer", () => {
  it("shows a text file exactly, tabs and blank lines included", async () => {
    const o = await open("notes.txt", enc("line one\nline two\n\n\tindented <b>tag</b> & &amp;\n"));
    expect(shownText(o.host)).toBe("line one\nline two\n\n\tindented <b>tag</b> & &amp;");
    expect(o.host.querySelector("b")).toBeNull();
    expect(o.statuses.at(-1)).toEqual({ phase: "ready" });
    expect(o.warnings).toEqual([]);
  });

  it("reads UTF-16 and windows-1252 files as the text they hold", async () => {
    const s = "Zażółć gęślą jaźń\nline 2 ✓";
    const le = [0xff, 0xfe, ...[...s].flatMap((c) => [c.charCodeAt(0) & 0xff, c.charCodeAt(0) >> 8])];
    expect(shownText((await open("u16.txt", Uint8Array.from(le))).host)).toBe(s);
    const latin = Uint8Array.from([...enc("caf"), 0xe9, 0x20, 0x80]);
    expect(shownText((await open("old.log", latin)).host)).toBe("café €");
  });

  it("makes bidirectional overrides and controls visible instead of obeying them", async () => {
    const spoof = `access = "user${ch(0x202e)} ${ch(0x2066)}// admin${ch(0x2069)}${ch(0x202c)}";\u0007\u001b[31m`;
    const o = await open("check.js", enc(spoof));
    const shown = shownText(o.host);
    for (const c of [0x202e, 0x2066, 0x2069, 0x202c]) expect(shown.includes(ch(c))).toBe(false);
    expect(shown).toContain("<U+202E>");
    expect(shown).toContain("<U+2066>");
    expect(shown).toContain(ch(0x2407));
    expect(shown).toContain(ch(0x241b));
  });

  it("refuses a file that is not text, and draws nothing", async () => {
    const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
    for (const name of ["a.txt", "a.json", "a.md", "a.log"]) {
      const o = await open(name, png);
      expect(o.statuses.at(-1), name).toEqual({ phase: "error", error: { code: "text_binary" } });
      expect(o.host.querySelector(".exav-viewer-text"), name).toBeNull();
    }
    // A text with a few NULs in it is not one either.
    expect((await open("a.txt", enc("hello\0world"))).statuses.at(-1)).toMatchObject({ phase: "error" });
  });

  it("cuts a file past the byte limit, says so, and draws no more than the limit holds", async () => {
    // 100-byte lines: 3 MiB of them is 31,000 lines, under the line limit.
    const row = `${"x".repeat(98)}\n`;
    const big = enc(row.repeat(Math.ceil((MAX_BYTES * 1.5) / 99)));
    expect(big.length).toBeGreaterThan(MAX_BYTES);
    const o = await open("big.log", big);
    await settle();
    expect(o.warnings.map((w) => w.key)).toEqual(["text_truncated"]);
    const text = shownText(o.host);
    expect(text.length).toBeLessThanOrEqual(MAX_BYTES);
    expect(text.length).toBeGreaterThan(MAX_BYTES - 200);
    expect(text.split("\n").length).toBeLessThan(MAX_LINES);
    expect(text.startsWith(`${"x".repeat(98)}\n${"x".repeat(98)}`)).toBe(true);
  });

  it("cuts a file that is too long in lines though small in bytes", async () => {
    const o = await open("lines.txt", enc("x\n".repeat(MAX_LINES + 500)));
    await settle();
    expect(o.warnings.map((w) => w.key)).toEqual(["text_truncated"]);
    expect(shownText(o.host).split("\n").length).toBe(MAX_LINES);
  });

  it("draws a large file in blocks, the first at once and the others after", async () => {
    const o = await open("many.txt", enc("row\n".repeat(5000)));
    const blocks = () => o.host.querySelectorAll(".exav-viewer-text-chunk").length;
    expect(blocks()).toBeLessThan(25);
    expect(blocks()).toBeGreaterThan(0);
    await settle();
    expect(blocks()).toBe(25);
    expect(shownText(o.host).split("\n").length).toBe(5000);
  });

  it("stops drawing when the file is closed", async () => {
    const o = await open("many.txt", enc("row\n".repeat(20000)));
    const root = o.host.querySelector(".exav-viewer-text")!;
    const before = root.children.length;
    expect(before).toBeLessThan(100);
    o.handle.destroy();
    await settle();
    expect(o.host.querySelector(".exav-viewer-text")).toBeNull();
    expect(root.children.length).toBe(before);
  });

  it("cuts a very long line and counts it", async () => {
    const o = await open("one.txt", enc(`${"x".repeat(MAX_LINE * 5)}\nshort`));
    expect(o.warnings).toContainEqual({ key: "text_long_lines", count: 1 });
    const lines = shownText(o.host).split("\n");
    expect(lines[0]!.length).toBe(MAX_LINE + 1);
    expect(lines[0]!.endsWith("…")).toBe(true);
    expect(lines[1]).toBe("short");
  });

  it("draws a single huge line without a hang", async () => {
    const t = performance.now();
    const o = await open("min.json", enc(`[${'"abc",'.repeat(MAX_BYTES / 3)}1]`));
    await settle();
    expect(performance.now() - t).toBeLessThan(5000);
    expect(o.warnings.map((w) => w.key)).toContain("text_truncated");
  });
});

describe("JSON", () => {
  it("pretty prints, keeping each number as written", async () => {
    const o = await open("data.json", enc('{"big":12345678901234567890123,"price":1.10,"list":[1,2],"empty":{}}'));
    expect(shownText(o.host)).toBe(['{', '  "big": 12345678901234567890123,', '  "price": 1.10,', '  "list": [', '    1,', '    2', '  ],', '  "empty": {}', '}'].join("\n"));
    expect(o.warnings).toEqual([]);
    expect(o.host.querySelectorAll(".exav-viewer-text-key").length).toBe(4);
  });

  it("shows invalid JSON as it is, with a note", async () => {
    const src = '{"a": 1,}\n// comment';
    const o = await open("bad.json", enc(src));
    expect(shownText(o.host)).toBe(src);
    expect(o.warnings).toEqual([{ key: "text_not_json", count: 1 }]);
  });

  it("opens by type when the name says nothing", async () => {
    const o = await open("download", enc('{"a":1}'), "application/json");
    expect(shownText(o.host)).toBe('{\n  "a": 1\n}');
  });
});

describe("XML", () => {
  it("pretty prints, as text, with no element from the file", async () => {
    const o = await open("feed.xml", enc('<?xml version="1.0"?><feed><script>alert(1)</script><entry id="1"><title>Hi &amp; bye</title></entry></feed>'));
    expect(shownText(o.host)).toBe(
      ['<?xml version="1.0"?>', "<feed>", "  <script>alert(1)</script>", '  <entry id="1">', "    <title>Hi &amp; bye</title>", "  </entry>", "</feed>"].join("\n"),
    );
    expect(o.host.querySelector("script,feed,entry,title")).toBeNull();
    expect(o.warnings).toEqual([]);
  });

  it("notes markup that is not well formed", async () => {
    const o = await open("bad.xml", enc("<a><b></a>"));
    expect(o.warnings).toEqual([{ key: "text_not_xml", count: 1 }]);
    const plain = await open("no.xml", enc("just words"));
    expect(shownText(plain.host)).toBe("just words");
    expect(plain.warnings).toEqual([{ key: "text_not_xml", count: 1 }]);
  });

  it("does not show a SVG that way unless it is named as XML, and never draws it", async () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(2)</script></svg>';
    const o = await open("x.xml", enc(svg));
    expect(o.host.querySelector("svg,script")).toBeNull();
  });
});

describe("HTML", () => {
  it("is source text, with a note, and nothing in it is live", async () => {
    const html = '<!doctype html><html><body onload="alert(1)"><script src="https://evil.example/x.js"></script><img src="https://evil.example/p.png"><a href="javascript:alert(1)">x</a></body></html>';
    for (const name of ["page.html", "page.htm", "page.xhtml"]) {
      const o = await open(name, enc(html));
      expect(shownText(o.host), name).toBe(html);
      expect(o.warnings, name).toEqual([{ key: "text_html_source", count: 1 }]);
      expect(o.host.querySelector("script,img,a,html,body,iframe,link,style"), name).toBeNull();
    }
  });
});

describe("Markdown", () => {
  it("draws the document", async () => {
    const o = await open("README.md", enc("# Title\n\nSome *text* with [a link](https://example.com).\n\n- one\n- two\n"));
    expect(o.host.querySelector("h1")!.textContent).toBe("Title");
    expect(o.host.querySelector("em")!.textContent).toBe("text");
    expect(o.host.querySelector(".exav-viewer-text-link")!.textContent).toBe("a link");
    expect(o.host.querySelectorAll("li").length).toBe(2);
  });

  it("follows an http or https link on a click or Enter, as a PDF's links are, and no other", async () => {
    const opened: unknown[][] = [];
    const real = window.open;
    window.open = ((...args: unknown[]) => {
      opened.push(args);
      return null;
    }) as typeof window.open;
    try {
      const o = await open("links.md", enc("[a](https://example.com/a) [b](http://example.com/b) <https://example.com/c> [m](mailto:me@example.com) [x](javascript:alert(1))\n"));
      const links = [...o.host.querySelectorAll<HTMLElement>(".exav-viewer-text-link")];
      expect(links.map((l) => l.textContent)).toEqual(["a", "b", "https://example.com/c", "m"]);
      expect(links.map((l) => l.getAttribute("role"))).toEqual(["link", "link", "link", null]);
      expect(o.host.querySelector("a")).toBeNull();
      links[0]!.click();
      links[1]!.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
      links[1]!.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
      links[2]!.click();
      // The mail address is only text, and nothing else is a link.
      links[3]!.click();
      expect(opened).toEqual([
        ["https://example.com/a", "_blank", "noopener,noreferrer"],
        ["http://example.com/b", "_blank", "noopener,noreferrer"],
        ["https://example.com/c", "_blank", "noopener,noreferrer"],
      ]);
    } finally {
      window.open = real;
    }
  });

  it("makes nothing live of a hostile document", async () => {
    const md = [
      "# <img src=x onerror=alert(1)>",
      "<script>alert(1)</script>",
      "[x](javascript:alert(1)) [y](data:text/html,x) [z](/relative) [w](https://a.example@b.example/)",
      "![tracker](https://evil.example/pixel.png) ![d](data:image/svg+xml;base64,PHN2Zz4=)",
      "<iframe src=https://evil.example></iframe>",
    ].join("\n\n");
    const o = await open("evil.md", enc(md));
    expect(o.host.querySelector("a,img,script,iframe,svg,object,embed,link,style,form")).toBeNull();
    expect(o.host.querySelector(".exav-viewer-text-link")).toBeNull();
    for (const e of o.host.querySelectorAll("*")) for (const a of e.getAttributeNames()) expect(["class", "tabindex", "role"], a).toContain(a);
    expect(shownText(o.host)).toContain("<script>alert(1)</script>");
    expect(shownText(o.host)).toContain("[tracker]");
  });

  it("shows the text as it is, and says so, when the reader fails", async () => {
    engine.fail = true;
    try {
      const o = await open("broken.md", enc("# Title\n\n*text*\n"));
      expect(o.warnings).toEqual([{ key: "text_markdown_failed", count: 1 }]);
      expect(o.host.querySelector("h1,em")).toBeNull();
      expect(shownText(o.host)).toBe("# Title\n\n*text*");
      expect(o.statuses.at(-1)).toEqual({ phase: "ready" });
    } finally {
      engine.fail = false;
    }
  });

  it("cuts a long line and says so", async () => {
    const o = await open("long.md", enc(`${"word ".repeat(MAX_LINE)}\n\nend`));
    expect(o.warnings).toContainEqual({ key: "text_long_lines", count: 1 });
    expect(o.host.querySelector("p:last-child")!.textContent).toBe("end");
  });
});

describe("diffs and subtitles", () => {
  it("colours added, removed and hunk lines by class and leaves the text as it is", async () => {
    const diff = ["diff --git a/f b/f", "index 1..2 100644", "--- a/f", "+++ b/f", "@@ -1,2 +1,2 @@", " same", "-old", "+new"].join("\n");
    const o = await open("fix.patch", enc(diff));
    expect(shownText(o.host)).toBe(diff);
    const cls = (c: string) => [...o.host.querySelectorAll(`.${c}`)].map((e) => e.textContent);
    expect(cls("exav-viewer-text-add")).toEqual(["+new"]);
    expect(cls("exav-viewer-text-del")).toEqual(["-old"]);
    expect(cls("exav-viewer-text-hunk")).toEqual(["@@ -1,2 +1,2 @@"]);
    expect(cls("exav-viewer-text-meta")).toEqual(["diff --git a/f b/f", "index 1..2 100644", "--- a/f", "+++ b/f"]);
  });

  it("shows subtitles, YAML and source code as plain text", async () => {
    const srt = "1\n00:00:01,000 --> 00:00:02,500\nHello <i>there</i>\n";
    const o = await open("film.srt", enc(srt));
    expect(shownText(o.host)).toBe(srt.trimEnd());
    expect(o.host.querySelector("i")).toBeNull();
  });
});
