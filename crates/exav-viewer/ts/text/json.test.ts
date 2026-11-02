import { describe, expect, it } from "vitest";

import { formatJson, MAX_DEPTH } from "./json.js";
import { lineText } from "./lines.js";

const show = (text: string, max?: number) => {
  const r = formatJson(text, max);
  return r && r.lines.map(lineText).join("\n");
};

describe("formatJson", () => {
  it("indents by two spaces, one value per line", () => {
    expect(show('{"a":[1,2,{"b":null}],"c":"x","d":true}')).toBe(
      ['{', '  "a": [', '    1,', '    2,', '    {', '      "b": null', '    }', '  ],', '  "c": "x",', '  "d": true', '}'].join("\n"),
    );
  });

  it("keeps empty containers on one line", () => {
    expect(show('{"a":{},"b":[ ],"c":[[]]}')).toBe(['{', '  "a": {},', '  "b": [],', '  "c": [', '    []', '  ]', '}'].join("\n"));
  });

  it("keeps the text of numbers and strings exactly", () => {
    const src = '[12345678901234567890123,1.10,-0,1E+2,0.1e-7,"\\u00e9\\n\\/","é"]';
    const out = show(src)!;
    // JSON.parse would print 1.2345678901234568e+22, 1.1, 0 and decode the escapes.
    for (const token of ["12345678901234567890123", "1.10", "-0", "1E+2", "0.1e-7", '"\\u00e9\\n\\/"', '"é"']) expect(out).toContain(token);
  });

  it("keeps key order and duplicate keys", () => {
    expect(show('{"b":1,"a":2,"b":3}')).toBe('{\n  "b": 1,\n  "a": 2,\n  "b": 3\n}');
  });

  it("says the same thing as the input: parsing the output gives the parsed input", () => {
    const samples = [
      '{"menu":{"id":"file","items":[{"label":"New","shortcut":null},{"label":"Open","n":[1,2.5,-3e2]}],"on":false}}',
      "[[],{},[[[]]],\"a\\\"b\"]",
      '"just a string"',
      "  42  ",
      '{ "a" : 1 ,\n\t"b" : [ 1 , 2 ] }',
    ];
    for (const s of samples) expect(JSON.parse(show(s)!), s).toEqual(JSON.parse(s));
  });

  it("marks the parts so that they can be coloured, without changing the text", () => {
    const r = formatJson('{"k":"v","n":1,"t":null}')!;
    const segs = r.lines.flatMap((l) => (typeof l === "string" ? [] : l));
    expect(segs.filter((s) => s[1] === "exav-viewer-text-key").map((s) => s[0])).toEqual(['"k"', '"n"', '"t"']);
    expect(segs.filter((s) => s[1] === "exav-viewer-text-str").map((s) => s[0])).toEqual(['"v"']);
    expect(segs.filter((s) => s[1] === "exav-viewer-text-num").map((s) => s[0])).toEqual(["1"]);
    expect(segs.filter((s) => s[1] === "exav-viewer-text-lit").map((s) => s[0])).toEqual(["null"]);
  });

  it("refuses what is not strict JSON", () => {
    const bad = [
      "", "   ", "{", "}", "[1,]", "[,1]", "{\"a\":1,}", "{'a':1}", "{a:1}", "[1 2]", '{"a" 1}', '{"a":}', "[1]x", "[1][2]",
      "// c\n[1]", "[1 /* c */]", "NaN", "[Infinity]", "[01]", "[1.]", "[.5]", "[+1]", "[1e]", "[-]", "[tru]", "[nulll]", "[True]",
      '"unterminated', '"bad \\x escape"', '"\\u12G4"', '"raw\nnewline"', '"raw\ttab"', '{"a":1 "b":2}', '{"a":1:2}', '{1:2}', '[{]}',
    ];
    for (const s of bad) expect(formatJson(s), JSON.stringify(s)).toBeNull();
  });

  it("refuses nesting deeper than the limit, and accepts it at the limit", () => {
    const deep = (n: number) => "[".repeat(n) + "]".repeat(n);
    expect(formatJson(deep(MAX_DEPTH))).not.toBeNull();
    expect(formatJson(deep(MAX_DEPTH + 1))).toBeNull();
    const objects = (n: number) => '{"a":'.repeat(n) + "1" + "}".repeat(n);
    expect(formatJson(objects(MAX_DEPTH))).not.toBeNull();
    expect(formatJson(objects(MAX_DEPTH + 1))).toBeNull();
  });

  it("stops keeping lines at the cap and says so", () => {
    const text = `[${Array.from({ length: 1000 }, (_, i) => i).join(",")}]`;
    const r = formatJson(text, 100)!;
    expect(r.lines).toHaveLength(100);
    expect(r.more).toBe(true);
    expect(r.lines.map(lineText).slice(0, 3)).toEqual(["[", "  0,", "  1,"]);
    expect(formatJson(text, 5000)!.more).toBe(false);
  });

  it("is quick on hostile input", () => {
    const t = performance.now();
    for (const s of [
      "[".repeat(2_000_000),
      '{"a":'.repeat(400_000),
      '["' + "\\".repeat(1_000_001),
      "[" + "1,".repeat(1_000_000) + "1]",
      "[" + '"x",'.repeat(500_000) + '"x"',
      '"' + "a".repeat(2_000_000) + '"',
      "[" + '{"a":[]},'.repeat(200_000) + "{}]",
    ]) {
      formatJson(s, 50_000);
    }
    expect(performance.now() - t).toBeLessThan(5000);
  });
});
