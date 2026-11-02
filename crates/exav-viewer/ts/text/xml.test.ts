import { describe, expect, it } from "vitest";

import { lineText } from "./lines.js";
import { formatXml } from "./xml.js";

const show = (text: string, max?: number) => {
  const r = formatXml(text, max);
  return r && r.lines.map(lineText).join("\n");
};

describe("formatXml", () => {
  it("indents elements and keeps text on its element's line", () => {
    const out = show('<?xml version="1.0"?><feed><entry id="1" lang=\'fr\'><title>Hello</title><empty/><e></e></entry><!-- note --></feed>');
    expect(out).toBe(
      ['<?xml version="1.0"?>', "<feed>", '  <entry id="1" lang=\'fr\'>', "    <title>Hello</title>", "    <empty/>", "    <e></e>", "  </entry>", "  <!-- note -->", "</feed>"].join("\n"),
    );
  });

  it("puts long or multi-line text on lines of its own", () => {
    expect(show("<a>one\n   two</a>")).toBe(["<a>", "  one", "  two", "</a>"].join("\n"));
    const long = "x".repeat(300);
    expect(show(`<a>${long}</a>`)).toBe(["<a>", `  ${long}`, "</a>"].join("\n"));
  });

  it("shows CDATA, comments, processing instructions and a DOCTYPE as written", () => {
    const out = show('<!DOCTYPE note [<!ENTITY a "x>y">]><note><![CDATA[<b>&a;</b>]]><?pi do it?></note>')!;
    expect(out).toBe(['<!DOCTYPE note [<!ENTITY a "x>y">]>', "<note>", "  <![CDATA[<b>&a;</b>]]>", "  <?pi do it?>", "</note>"].join("\n"));
  });

  it("never expands an entity or follows an external one", () => {
    const xxe = '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd"><!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><r>&xxe; &lol2; &#60;script&#62;</r>';
    const out = show(xxe)!;
    expect(out).toContain('<!ENTITY xxe SYSTEM "file:///etc/passwd">');
    expect(out).toContain("&xxe; &lol2; &#60;script&#62;");
    expect(out).not.toContain("<script>");
    expect(out).not.toContain("lollol");
  });

  it("keeps attribute values with a '>' in them inside their tag", () => {
    expect(show('<a href="x>y" b=\'1>2\'>t</a>')).toBe('<a href="x>y" b=\'1>2\'>t</a>');
  });

  it("is not XML when it does not start with markup", () => {
    expect(formatXml("hello <b>world</b>")).toBeNull();
    expect(formatXml("")).toBeNull();
    expect(formatXml("   \n")).toBeNull();
    expect(formatXml("{}")).toBeNull();
  });

  it("says when the markup is not well formed, and still shows it all", () => {
    const cases: [string, boolean][] = [
      ["<a><b></b></a>", true],
      ["<a><b></a></b>", false],
      ["<a><b>", false],
      ["<a></a></a>", false],
      ["<a><!-- never closed", false],
      ["<a x='1", false],
      ["<a>1 < 2</a>", true],
    ];
    for (const [src, ok] of cases) {
      const r = formatXml(src)!;
      expect(r.wellFormed, src).toBe(ok);
      // Everything typed is somewhere in the output, in order.
      const flat = r.lines.map(lineText).join("").replace(/\s+/g, "");
      expect(flat, src).toBe(src.replace(/\s+/g, ""));
    }
  });

  it("marks tags, attributes and values for colour", () => {
    const r = formatXml('<a k="v">t</a>')!;
    const segs = r.lines.flatMap((l) => (typeof l === "string" ? [] : l));
    expect(segs.filter((s) => s[1] === "exav-viewer-text-tag").map((s) => s[0])).toEqual(["a", "a"]);
    expect(segs.filter((s) => s[1] === "exav-viewer-text-attr").map((s) => s[0])).toEqual(["k"]);
    expect(segs.filter((s) => s[1] === "exav-viewer-text-str").map((s) => s[0])).toEqual(['"v"']);
  });

  it("stops at the line cap", () => {
    const text = `<r>${"<i>1</i>".repeat(1000)}</r>`;
    const r = formatXml(text, 10)!;
    expect(r.lines).toHaveLength(10);
    expect(r.more).toBe(true);
  });

  it("limits indentation however deep the document nests", () => {
    const out = show("<a>".repeat(5000) + "x" + "</a>".repeat(5000), 6000)!;
    const widest = Math.max(...out.split("\n").map((l) => l.length - l.trimStart().length));
    expect(widest).toBeLessThanOrEqual(200);
  });

  it("is quick on hostile input", () => {
    const t = performance.now();
    for (const s of [
      "<".repeat(1_000_000),
      "<a ".repeat(500_000),
      "<a>".repeat(600_000),
      "<!--".repeat(500_000),
      "<![CDATA[".repeat(200_000),
      '<a b="'.repeat(300_000),
      "<?".repeat(1_000_000),
      "<!DOCTYPE [".repeat(200_000),
      "<a>x</b>".repeat(250_000),
      "<a></a>".repeat(250_000),
      "<</>".repeat(500_000),
    ]) {
      formatXml(s, 50_000);
    }
    expect(performance.now() - t).toBeLessThan(6000);
  });
});
