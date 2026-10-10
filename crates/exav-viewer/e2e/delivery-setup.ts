// The tests' files, written into e2e/.out/ before the run: the samples
// (fixtures/make-samples.mjs, into .out/samples/), and the large files the
// delivery tests open (delivery.spec.ts), served from there by the demo's
// `vite preview` (demo/vite.config.ts) with range requests:
//
// - big.pdf: 12 pages, each an uncompressed grey image of 400 KB, the page
//   objects first and the images after, so that a page needs its own image
//   and nothing of the others';
// - big.zip: a PNG, then 15 stored members of random bytes, 1 MiB each;
// - spaced.zip: 80 stored members of random bytes, 128 KiB apart with unclaimed
//   bytes between them, too scattered for the ranged reader;
// - clip.webm: 12 s of noise and a moving bar, VP8, recorded by Playwright's
//   own video capture (its ffmpeg), so that no encoder is needed here.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";

import { storedZip } from "./zip.js";

const here = path.dirname(fileURLToPath(import.meta.url));
export const OUT = path.join(here, ".out");

/** Deterministic bytes: the same files on every machine. */
function noise(n: number, seed: number): Uint8Array {
  const out = new Uint8Array(n);
  let s = seed >>> 0 || 1;
  for (let i = 0; i < n; i++) {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    out[i] = s & 0xff;
  }
  return out;
}

export const PDF_PAGES = 12;
const IMAGE_SIDE = 640;

export function bigPdf(): Buffer {
  const objects: (Buffer | string)[] = [];
  const add = (body: Buffer | string) => objects.push(body) && objects.length;
  const catalog = add("");
  const pages = add("");
  const pageIds: number[] = [];
  const contentIds: number[] = [];
  const imageIds: number[] = [];
  for (let i = 0; i < PDF_PAGES; i++) pageIds.push(add(""));
  for (let i = 0; i < PDF_PAGES; i++) {
    const shade = (i + 1) / (PDF_PAGES + 1);
    const content = `q ${shade.toFixed(3)} g 50 680 512 60 re f Q q 512 0 0 512 50 100 cm /Im Do Q`;
    contentIds.push(add(`<< /Length ${content.length} >>\nstream\n${content}\nendstream`));
  }
  for (let i = 0; i < PDF_PAGES; i++) {
    const pixels = Buffer.from(noise(IMAGE_SIDE * IMAGE_SIDE, i + 1));
    const head = `<< /Type /XObject /Subtype /Image /Width ${IMAGE_SIDE} /Height ${IMAGE_SIDE} /ColorSpace /DeviceGray /BitsPerComponent 8 /Length ${pixels.length} >>\nstream\n`;
    imageIds.push(add(Buffer.concat([Buffer.from(head), pixels, Buffer.from("\nendstream")])));
  }
  objects[catalog - 1] = `<< /Type /Catalog /Pages ${pages} 0 R >>`;
  objects[pages - 1] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${PDF_PAGES} >>`;
  pageIds.forEach((id, i) => {
    objects[id - 1] = `<< /Type /Page /Parent ${pages} 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im ${imageIds[i]} 0 R >> >> /Contents ${contentIds[i]} 0 R >>`;
  });
  const parts: Buffer[] = [Buffer.from("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  let at = parts[0]!.length;
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(at);
    const b = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`), Buffer.from(body), Buffer.from("\nendobj\n")]);
    parts.push(b);
    at += b.length;
  });
  const xref = [`xref\n0 ${objects.length + 1}\n`, "0000000000 65535 f \n", ...offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`)].join("");
  parts.push(Buffer.from(`${xref}trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R >>\nstartxref\n${at}\n%%EOF\n`));
  return Buffer.concat(parts);
}

export const ZIP_PICTURE = "picture.png";

export function bigZip(): Buffer {
  const png = fs.readFileSync(path.join(OUT, "samples", "landscape.png"));
  const files: [string, Uint8Array][] = [[ZIP_PICTURE, png]];
  for (let i = 1; i <= 15; i++) files.push([`data-${String(i).padStart(2, "0")}.bin`, noise(1024 * 1024, 100 + i)]);
  return storedZip(files);
}

export const SPACED_MEMBERS = 80;

/**
 * A ZIP the ranged reader cannot list: each member starts on a 128 KiB
 * boundary, after 32 bytes no header claims. Listing reads those bytes (they
 * could hold a hidden member), each in a 64 KiB block of its own, one round
 * of reads per block, which is more rounds than the reader allows
 * (RANGED_ARCHIVE.maxRounds).
 */
export function spacedZip(): Buffer {
  const GAP = 32;
  const files: [string, Uint8Array][] = [];
  for (let i = 0; i < SPACED_MEMBERS; i++) {
    const name = `m-${String(i).padStart(3, "0")}.bin`;
    files.push([name, noise(128 * 1024 - 30 - name.length - GAP, 500 + i)]);
  }
  return storedZip(files, GAP);
}

/** A page whose picture changes every frame, recorded as Playwright records any page. */
async function recordClip(to: string): Promise<void> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "exav-clip-"));
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({ viewport: { width: 480, height: 270 }, recordVideo: { dir, size: { width: 480, height: 270 } } });
    const page = await context.newPage();
    await page.setContent(`<body style="margin:0"><canvas width="480" height="270"></canvas><script>
      const c = document.querySelector("canvas").getContext("2d");
      const img = c.createImageData(480, 270);
      let s = 1, f = 0;
      (function draw() {
        for (let i = 0; i < img.data.length; i += 4) { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; img.data[i] = img.data[i + 1] = img.data[i + 2] = s & 255; img.data[i + 3] = 255; }
        c.putImageData(img, 0, 0);
        c.fillStyle = "#e33"; c.fillRect((f++ * 4) % 480, 100, 40, 70);
        requestAnimationFrame(draw);
      })();
    </script></body>`);
    await page.waitForTimeout(12_000);
    await context.close();
    fs.copyFileSync((await page.video()!.path()), to);
  } finally {
    await browser.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export default async function setup(): Promise<void> {
  fs.mkdirSync(OUT, { recursive: true });
  execFileSync(process.execPath, [path.join(here, "fixtures", "make-samples.mjs")], { stdio: "inherit" });
  fs.writeFileSync(path.join(OUT, "big.pdf"), bigPdf());
  fs.writeFileSync(path.join(OUT, "big.zip"), bigZip());
  fs.writeFileSync(path.join(OUT, "spaced.zip"), spacedZip());
  // Recorded in real time: kept once made (delete e2e/.out/ to remake it).
  const clip = path.join(OUT, "clip.webm");
  if (!fs.existsSync(clip)) await recordClip(clip);
}
