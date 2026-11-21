import { describe, expect, it } from "vitest";

import { clip, MAX_LINE, sanitize, splitLines } from "./decode.js";

const ch = (code: number) => String.fromCharCode(code);

describe("sanitize", () => {
  it("makes every bidirectional mark, override, embedding and isolate visible", () => {
    const hidden = [0x61c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069];
    const text = `if (admin ${hidden.map(ch).join("")}) { // end`;
    const out = sanitize(text);
    for (const c of hidden) {
      expect(out.includes(ch(c)), c.toString(16)).toBe(false);
      expect(out).toContain(`<U+${c.toString(16).toUpperCase().padStart(4, "0")}>`);
    }
    // The text around them is as it was.
    expect(out.startsWith("if (admin ")).toBe(true);
    expect(out.endsWith(") { // end")).toBe(true);
  });

  it("shows C0 controls and DEL as their Control Pictures, and C1 and separators as code points", () => {
    expect(sanitize("a\u0001b")).toBe(`a${ch(0x2401)}b`);
    expect(sanitize("a\u0000b")).toBe(`a${ch(0x2400)}b`);
    expect(sanitize(`a${ch(0x7f)}b`)).toBe(`a${ch(0x2421)}b`);
    expect(sanitize(`a${ch(0x85)}b`)).toBe("a<U+0085>b");
    expect(sanitize(`a${ch(0x2028)}b${ch(0x2029)}c`)).toBe("a<U+2028>b<U+2029>c");
  });

  it("leaves tabs, line breaks and ordinary text, right-to-left included, alone", () => {
    const text = "a\tb\r\nc\nd שלום مرحبا 日本語 😀";
    expect(sanitize(text)).toBe(text);
  });
});

describe("splitLines", () => {
  it("splits on LF, CRLF and CR", () => {
    expect(splitLines("a\nb\r\nc\rd").lines).toEqual(["a", "b", "c", "d"]);
    expect(splitLines("a\n\nb").lines).toEqual(["a", "", "b"]);
    expect(splitLines("").lines).toEqual([""]);
    expect(splitLines("a\n").lines).toEqual(["a", ""]);
  });

  it("stops at the cap and says there was more", () => {
    const text = Array.from({ length: 10 }, (_, i) => `l${i}`).join("\n");
    expect(splitLines(text, 4)).toEqual({ lines: ["l0", "l1", "l2", "l3"], more: true });
    expect(splitLines(text, 10).more).toBe(false);
    expect(splitLines(text, 10).lines).toHaveLength(10);
    // The newline that ends the text does not start a line.
    expect(splitLines("a\nb\n", 2)).toEqual({ lines: ["a", "b"], more: false });
    expect(splitLines("a\nb\nc", 2)).toEqual({ lines: ["a", "b"], more: true });
  });

  it("handles a million newlines in linear time", () => {
    const t = performance.now();
    const r = splitLines("\n".repeat(1_000_000), 50_000);
    expect(r.lines).toHaveLength(50_000);
    expect(r.more).toBe(true);
    expect(performance.now() - t).toBeLessThan(1000);
  });
});

describe("clip", () => {
  it("leaves a line that fits and cuts one that does not, with an ellipsis", () => {
    expect(clip("abc", 3)).toBe("abc");
    expect(clip("abcd", 3)).toBe("abc…");
    expect(clip("x".repeat(MAX_LINE + 1)).length).toBe(MAX_LINE + 1);
  });

  it("does not cut a surrogate pair in two", () => {
    const s = "ab😀cd";
    expect(clip(s, 3)).toBe("ab…");
    expect(clip(s, 4)).toBe("ab😀…");
  });
});
