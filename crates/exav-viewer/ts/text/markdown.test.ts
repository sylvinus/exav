// The reader's own behaviour is tested in exav-render (tests/markdown.rs). Here:
// what the page makes of a tree, with the real module in this process.
import { describe, expect, it } from "vitest";

import { splitLines } from "./decode.js";
import { safeTarget, type Block, type Inline } from "./markdown.js";
import { drawBlocks } from "./markdown-view.js";
import { readMarkdown } from "../test/markdown.js";

const TAGS = new Set(["P", "H1", "H2", "H3", "H4", "H5", "H6", "PRE", "CODE", "HR", "BLOCKQUOTE", "UL", "OL", "LI", "TABLE", "THEAD", "TBODY", "TR", "TH", "TD", "EM", "STRONG", "DEL", "BR", "SPAN"]);

async function render(md: string): Promise<HTMLElement> {
  const root = document.createElement("div");
  drawBlocks(root, (await readMarkdown(splitLines(md).lines.join("\n"))).blocks);
  return root;
}

function drawTree(blocks: Block[]): HTMLElement {
  const root = document.createElement("div");
  drawBlocks(root, blocks);
  return root;
}

/**
 * What may be in the page after any Markdown: only these tags, and no attribute
 * but a class, a list's start, and on a followable link the fixed `tabindex="0"`
 * and `role="link"`.
 */
function expectInert(root: HTMLElement, label = "") {
  for (const e of root.querySelectorAll("*")) {
    expect(TAGS.has(e.tagName), `${label} <${e.tagName}>`).toBe(true);
    for (const a of e.getAttributeNames()) expect(["class", "start", "tabindex", "role"].includes(a), `${label} ${e.tagName} ${a}`).toBe(true);
    if (e.hasAttribute("tabindex")) expect([e.getAttribute("tabindex"), e.getAttribute("role"), e.className], label).toEqual(["0", "link", "exav-viewer-text-link"]);
    if (e.hasAttribute("start")) expect(e.getAttribute("start")).toMatch(/^\d{1,9}$/);
  }
}

const tags = (root: HTMLElement, selector: string) => [...root.querySelectorAll(selector)].map((e) => e.textContent);

describe("a document, read and drawn", () => {
  it("draws headings, emphasis, code, quotes, lists, rules and tables", async () => {
    const r = await render("# One\n\nSome *em* and **strong** and ~~gone~~ and `co*de*`.\n\n> quoted\n\n- a\n- b\n\n3. three\n\n---\n\n| A | B |\n|:-|-:|\n| 1 | 2 |\n\n```\nfenced <b>\n```\n");
    expect(tags(r, "h1")).toEqual(["One"]);
    expect(tags(r, "em")).toEqual(["em"]);
    expect(tags(r, "strong")).toEqual(["strong"]);
    expect(tags(r, "del")).toEqual(["gone"]);
    expect(tags(r, "code")).toEqual(["co*de*", "fenced <b>"]);
    expect(tags(r, "blockquote")).toEqual(["quoted"]);
    expect(tags(r, "ul > li")).toEqual(["a", "b"]);
    expect(r.querySelector("ol")!.getAttribute("start")).toBe("3");
    expect(r.querySelectorAll("hr").length).toBe(1);
    expect(tags(r, "th")).toEqual(["A", "B"]);
    expect(r.querySelectorAll("th")[1]!.className).toBe("exav-viewer-md-right");
    expect(tags(r, "td")).toEqual(["1", "2"]);
    expectInert(r);
  });

  it("makes a loose list of paragraphs and a tight one of bare text", async () => {
    expect((await render("- a\n- b")).querySelectorAll("li > p").length).toBe(0);
    expect((await render("- a\n\n- b")).querySelectorAll("li > p").length).toBe(2);
  });

  it("decodes entities and resolves reference links", async () => {
    const r = await render("fish &amp; chips &lt;b&gt;\n\n[ref][1]\n\n[1]: https://example.com/r");
    expect(r.textContent).toContain("fish & chips <b>");
    expect(tags(r, ".exav-viewer-text-link")).toEqual(["ref"]);
    expect(tags(r, ".exav-viewer-text-url")).toEqual([" (https://example.com/r)"]);
  });
});

describe("links", () => {
  const link = async (md: string) => {
    const r = await render(md);
    return { r, spans: tags(r, ".exav-viewer-text-link"), urls: tags(r, ".exav-viewer-text-url") };
  };

  it("keeps http, https and mailto targets, and writes the address out beside the label", async () => {
    const a = await link("[docs](https://example.com/a?b=1)");
    expect(a.spans).toEqual(["docs"]);
    expect(a.urls).toEqual([" (https://example.com/a?b=1)"]);
    expect((await link("[site](http://example.com)")).urls).toEqual([" (http://example.com/)"]);
    expect((await link("[write](mailto:me@example.com)")).urls).toEqual([" (mailto:me@example.com)"]);
    // A label that is the address says it once.
    expect((await link("[https://example.com/](https://example.com/)")).urls).toEqual([]);
    expect((await link("<https://example.com/x>")).spans).toEqual(["https://example.com/x"]);
    expect((await link("<me@example.com>")).spans).toEqual(["me@example.com"]);
  });

  it("never makes an anchor, an image or a form", async () => {
    const r = await render("[a](https://example.com) ![b](https://example.com/i.png) <a href='https://x'>c</a> <https://example.com>");
    expect(r.querySelector("a,img,form,iframe,object,embed,input,button,script,link,style")).toBeNull();
  });

  it("keeps only the label of any other target", async () => {
    const refused = [
      "javascript:alert(1)", "JaVaScRiPt:alert(1)", "  javascript:alert(1)", "java\nscript:alert(1)", "java\tscript:alert(1)",
      "&#106;avascript:alert(1)", "data:text/html,<script>alert(1)</script>", "vbscript:msgbox(1)", "file:///etc/passwd",
      "ftp://example.com/x", "blob:https://example.com/1", "about:blank", "/relative/path", "../up", "page.html", "#anchor", "//evil.example/x",
      "https://user:pass@example.com/", "https://google.com@evil.example/", "https://", "mailto:", "tel:+123",
      `https://exa${String.fromCharCode(0x202e)}mple.com/`, "https://example.com/a b", "x".repeat(3000),
    ];
    for (const target of refused) {
      // In angle brackets, which allow spaces, and bare, for a target with none.
      const forms = [`[click me](<${target.replace(/[<>\n]/g, " ")}>)`, ...(/[\s()<>]/.test(target) ? [] : [`[click me](${target})`])];
      for (const md of forms) {
        const { r, spans, urls } = await link(md);
        expect(spans, md).toEqual([]);
        expect(urls, md).toEqual([]);
        expect(r.textContent, md).toContain("click me");
        expectInert(r, md);
      }
    }
  });

  it("checks the address again, whatever the tree says", () => {
    const hostile = ["javascript:alert(1)", "https://user:pass@example.com/", "data:text/html,x", "/relative", "HTTPS://", "https://exa‮mple.com/"];
    for (const url of hostile) {
      const r = drawTree([{ t: "p", c: [{ t: "link", url, c: [{ t: "text", s: "label" }] }] }]);
      expect(tags(r, ".exav-viewer-text-link"), url).toEqual([]);
      expect(r.textContent, url).toBe("label");
      expectInert(r, url);
    }
  });

  it("uses the browser's own reading of the address, so a lookalike host is shown as it really is", () => {
    expect(safeTarget("https://EXAMPLE.com:443/a")).toBe("https://example.com/a");
    expect(safeTarget(`https://${String.fromCharCode(0x430)}pple.com/`)).toBe("https://xn--pple-43d.com/");
  });

  it("shows an image as its alt text, in brackets, and loads nothing", async () => {
    const r = await render("![a diagram](https://example.com/d.png) ![](https://example.com/e.png) ![x](data:image/png;base64,AAAA)");
    expect(r.querySelector("img")).toBeNull();
    expect(tags(r, ".exav-viewer-md-image")).toEqual(["[a diagram]", "[image]", "[x]"]);
    expect(r.textContent).not.toContain("example.com");
    expect(r.textContent).not.toContain("base64");
  });
});

describe("raw HTML is text", () => {
  const hostile = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)><circle r=1></circle></svg>",
    "<iframe src=javascript:alert(1)></iframe>",
    "<a href=\"javascript:alert(1)\">x</a>",
    "<style>*{background:url(https://evil.example/x)}</style>",
    "<form action=https://evil.example><input name=p></form>",
    "<details open ontoggle=alert(1)>",
    "<!-- comment --><b>bold</b>",
    "<math><mi xlink:href=data:x,alert(1)>",
    "<meta http-equiv=refresh content='0;url=https://evil.example'>",
    "<link rel=stylesheet href=https://evil.example/x.css>",
    "<base href=https://evil.example/>",
    "</p><script>alert(1)</script>",
  ];

  it("shows each of these as written and creates none of their elements", async () => {
    for (const html of hostile) {
      const r = await render(html);
      expect(r.querySelector("script,img,svg,iframe,a,style,form,input,details,math,meta,link,base,b"), html).toBeNull();
      expectInert(r, html);
      expect(r.textContent, html).toBe(html);
    }
  });

  it("does so inside every Markdown construct", async () => {
    const html = "<img src=x onerror=alert(1)>";
    const wrapped = [`# ${html}`, `> ${html}`, `- ${html}`, `1. ${html}`, `*${html}*`, `**${html}**`, `[${html}](https://example.com)`, `![${html}](https://example.com/i.png)`, `| ${html} |\n|---|\n| ${html} |`, `\`${html}\``, `\`\`\`\n${html}\n\`\`\``, `    ${html}`];
    for (const md of wrapped) {
      const r = await render(md);
      expect(r.querySelector("img"), md).toBeNull();
      expectInert(r, md);
      expect(r.textContent, md).toContain(html.slice(0, 4));
    }
  });
});

describe("limits", () => {
  const sizes = (n: number, s: string) => s.repeat(n);
  const inputs: [string, string][] = [
    ["100k stars", sizes(100_000, "*")],
    ["closers only", sizes(40, `${sizes(3000, "a* ")}\n`)],
    ["alternating emphasis", sizes(50_000, "*a_b")],
    ["100k open brackets", sizes(100_000, "[")],
    ["100k link openers", sizes(100_000, "[](")],
    ["100k image openers", sizes(100_000, "![")],
    ["nested links", sizes(20_000, "[a](") + sizes(20_000, ")")],
    ["ascending backtick runs", Array.from({ length: 1500 }, (_, i) => "`".repeat(i + 1)).join(" ")],
    ["autolink openers", sizes(30_000, "<http://a")],
    ["one 1 MB line of words", sizes(200_000, "word ")],
    ["10k nested quotes", sizes(10_000, "> ") + "deep"],
    ["quote staircase", Array.from({ length: 2000 }, (_, i) => "> ".repeat(i % 40) + "x").join("\n")],
    ["nested list on one line", sizes(10_000, "- ") + "deep"],
    ["list staircase", Array.from({ length: 3000 }, (_, i) => " ".repeat(2 * (i % 60)) + "- item").join("\n")],
    ["20k blank-separated items", sizes(20_000, "- a\n\n")],
    ["50k headings", sizes(50_000, "# h\n")],
    ["wide table", "|" + sizes(5000, "a|") + "\n|" + sizes(5000, "-|") + "\n" + sizes(2000, "|" + sizes(100, "x|") + "\n")],
    ["long table", "|a|b|\n|-|-|\n" + sizes(50_000, "|1|2|\n")],
    ["html storm", sizes(30_000, "<div><script>")],
    ["emphasis inside a link inside a quote", sizes(5000, "> [*a **b ") + sizes(5000, "](x)")],
  ];

  for (const [name, md] of inputs) {
    it(`bounds the work and the page for ${name}`, async () => {
      const t = performance.now();
      const lines = splitLines(md, 50_000).lines.map((l) => l.slice(0, 10_000));
      const parsed = await readMarkdown(lines.join("\n"));
      const elapsed = performance.now() - t;
      expect(elapsed, `${elapsed | 0} ms`).toBeLessThan(3000);
      const root = document.createElement("div");
      drawBlocks(root, parsed.blocks);
      expect(root.querySelectorAll("*").length).toBeLessThan(250_000);
      expectInert(root, name);
    });
  }

  it("stops nesting quotes and lists at the limit, and keeps the rest as text", async () => {
    const r = await render(sizes(50, "> ") + "deep text");
    expect(r.querySelectorAll("blockquote").length).toBe(10);
    expect(r.querySelector(".exav-viewer-md-raw")!.textContent).toContain("deep text");
    const list = await render(Array.from({ length: 50 }, (_, i) => `${"  ".repeat(i)}- level${i}`).join("\n"));
    expect(list.querySelectorAll("ul").length).toBe(10);
    expect(list.textContent).toContain("level49");
  });

  it("stops at the node limit and says it was cut", async () => {
    const parsed = await readMarkdown(sizes(150_000, "x *y*\n\n"));
    expect(parsed.truncated).toBe(true);
    expect(parsed.blocks.length).toBeLessThan(150_000);
    expect((await readMarkdown("# small")).truncated).toBe(false);
  });

  it("draws a deeper tree than the reader makes without failing", () => {
    // The reader stops at 32 nested inlines; this is the page's own margin.
    let inline: Inline = { t: "text", s: "x" };
    for (let i = 0; i < 200; i++) inline = { t: "em", c: [inline] };
    const r = drawTree([{ t: "p", c: [inline] }]);
    expect(r.textContent).toBe("x");
    expectInert(r);
  });
});
