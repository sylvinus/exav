// The wasm check must refuse an import no list has and a module without its
// memory cap; the modules built here must carry their caps; and a decode
// that needs more than its module's cap must fail as a trap of that instance,
// the next instance working.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import zlib from "node:zlib";

import { describe, expect, it } from "vitest";

import { checkModule, LISTS, MEMORY_CAPS, memoryLimits, moduleName } from "./check-wasm-imports.mjs";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const wasmDir = path.join(root, "wasm");

const leb = (n) => {
  const out = [];
  do {
    let b = n & 0x7f;
    n = Math.floor(n / 128);
    if (n) b |= 0x80;
    out.push(b);
  } while (n);
  return out;
};
const str = (s) => [...leb(s.length), ...Buffer.from(s)];
const section = (id, body) => [id, ...leb(body.length), ...body];

/** A module importing `imports` ([namespace, name] pairs) and defining a memory of `max` pages. */
function module(imports, max) {
  const bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  bytes.push(...section(1, [1, 0x60, 0, 0]));
  bytes.push(...section(2, [...leb(imports.length), ...imports.flatMap(([ns, name]) => [...str(ns), ...str(name), 0x00, 0x00])]));
  bytes.push(...section(5, max === null ? [1, 0x00, 1] : [1, 0x01, 1, ...leb(max)]));
  return new Uint8Array(bytes);
}

describe("the check", () => {
  it("passes a module whose imports are on its list and whose memory has its cap", () => {
    const bytes = module([["./exav_viewer_image_bg.js", "__wbg_Error_0123456789abcdef"]], MEMORY_CAPS.exav_viewer_image_bg);
    expect(checkModule("exav_viewer_image_bg", bytes).problems).toEqual([]);
  });

  it("refuses an import the list does not have", () => {
    const bytes = module(
      [
        ["./exav_viewer_image_bg.js", "__wbg_Error_0123456789abcdef"],
        ["./exav_viewer_image_bg.js", "__wbg_fetch_0123456789abcdef"],
      ],
      MEMORY_CAPS.exav_viewer_image_bg,
    );
    expect(checkModule("exav_viewer_image_bg", bytes).problems).toEqual(["imports not on its list: glue.__wbg_fetch"]);
    // A list's name under another namespace is another import.
    expect(checkModule("exav_viewer_image_bg", module([["env", "__wbg_Error"]], MEMORY_CAPS.exav_viewer_image_bg)).problems).toHaveLength(1);
  });

  it("refuses one of this package's modules without its memory cap", () => {
    expect(checkModule("exav_viewer_dwg_bg", module([], null)).problems).toEqual(["memory may grow to 4 GiB, not 32768 pages (scripts/build-wasm.sh)"]);
    expect(checkModule("exav_viewer_dwg_bg", module([], 65536)).problems).toHaveLength(1);
  });

  it("refuses a module it has no list for", () => {
    expect(checkModule("mystery_bg", module([], null)).problems).toEqual(["no import list for this module"]);
  });

  it("names a module as its file, without a bundler's hash", () => {
    expect(moduleName("docx_parser_bg-Bv5LdJhP.wasm")).toBe("docx_parser_bg");
    expect(moduleName("exav_viewer_image_bg-C3-uQLyR.wasm")).toBe("exav_viewer_image_bg");
    expect(moduleName("exav_viewer_model_bg.wasm")).toBe("exav_viewer_model_bg");
    expect(Object.keys(LISTS)).toContain(moduleName("qcms_bg.wasm"));
  });
});

describe("the modules built here", () => {
  it("carry the caps build-wasm.sh sets", () => {
    const script = fs.readFileSync(path.join(root, "scripts", "build-wasm.sh"), "utf8");
    const caps = {};
    for (const m of script.matchAll(/^\s*([\w| -]+)\) echo \$\(\((\d+) \* 1024 \* 1024\)\) ;;$/gm)) {
      for (const f of m[1].split("|").map((s) => s.trim())) caps[`exav_viewer_${f.replace("-", "_")}_bg`] = (Number(m[2]) * 1024 * 1024) / 65536;
    }
    expect(caps).toEqual(MEMORY_CAPS);
    for (const name of ["exav_viewer_image_bg", "exav_viewer_dwg_bg", "exav_viewer_model_bg"]) {
      expect(memoryLimits(fs.readFileSync(path.join(wasmDir, `${name}.wasm`)))?.max, name).toBe(MEMORY_CAPS[name]);
    }
  });

  it("trap on a decode that needs more than the cap, and a new instance works", async () => {
    // A grey PNG of 17000 x 17000 zeros: 289 MB of pixels, under the decoders'
    // own limit (512 MiB), whose RGBA copy (1.16 GB) does not fit in 1 GiB.
    const png = (w, h) => {
      const chunk = (type, body) => {
        const len = Buffer.alloc(4);
        len.writeUInt32BE(body.length);
        const crc = Buffer.alloc(4);
        crc.writeUInt32BE(zlib.crc32(Buffer.concat([Buffer.from(type), body])) >>> 0);
        return Buffer.concat([len, Buffer.from(type), body, crc]);
      };
      const ihdr = Buffer.alloc(13);
      ihdr.writeUInt32BE(w, 0);
      ihdr.writeUInt32BE(h, 4);
      ihdr[8] = 8; // depth
      ihdr[9] = 0; // grey
      const raw = Buffer.alloc((w + 1) * h);
      return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", zlib.deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
    };
    const bytes = fs.readFileSync(path.join(wasmDir, "exav_viewer_image_bg.wasm"));
    const instance = async () => {
      const glue = await import(`${pathToFileURL(path.join(wasmDir, "exav_viewer_image.js")).href}?${Math.random()}`);
      const exports = glue.initSync({ module: bytes });
      return { glue, exports };
    };
    const big = await instance();
    let error;
    try {
      big.glue.decodeImage(png(17000, 17000), Infinity);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(WebAssembly.RuntimeError);
    expect(big.exports.memory.buffer.byteLength).toBeLessThanOrEqual(MEMORY_CAPS.exav_viewer_image_bg * 65536);
    // The same picture, smaller, decodes on a fresh instance.
    const next = await instance();
    const image = next.glue.decodeImage(png(64, 32), Infinity);
    expect([image.width, image.height, image.takeRgba().length]).toEqual([64, 32, 64 * 32 * 4]);
  }, 120_000);
});
