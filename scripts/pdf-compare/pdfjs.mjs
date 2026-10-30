// node pdfjs.mjs LIST OUTDIR MAXPAGES: renders the first MAXPAGES pages of each PDF named in LIST
// (one path a line) at scale 1 on white in headless Chromium with the pdfjs-dist of the viewer, writes
// OUTDIR/<stem>-<page>.png, prints one JSON line per page: ms to render, size, or the failure.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";

// The viewer's node_modules (playwright, pdfjs-dist), a Linux install of it.
const root = process.env.EXAV_VIEWER_DIR ?? path.resolve(import.meta.dirname, "../../crates/exav-viewer");
const require = createRequire(root + "/package.json");
const { chromium } = require("playwright");
const pdfjs = path.join(root, "node_modules", "pdfjs-dist");

const [list, out, maxArg] = process.argv.slice(2);
const max = Number(maxArg);
const files = fs.readFileSync(list, "utf8").split("\n").filter(Boolean);

const server = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url.split("?")[0]);
  let file;
  if (url === "/") {
    res.setHeader("content-type", "text/html");
    return res.end("<!doctype html><meta charset=utf-8><body>");
  }
  if (url.startsWith("/pdfjs/")) file = path.join(pdfjs, url.slice(7));
  else if (url.startsWith("/file/")) file = files[Number(url.slice(6))];
  else return res.writeHead(404).end();
  fs.readFile(file, (e, d) => {
    if (e) return res.writeHead(404).end();
    res.setHeader("content-type", file.endsWith(".mjs") ? "text/javascript" : "application/octet-stream");
    res.end(d);
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch();
for (let n = 0; n < files.length; n++) {
  const stem = path.basename(files[n], path.extname(files[n]));
  const page = await (await browser.newContext({ deviceScaleFactor: 1 })).newPage();
  const timeout = setTimeout(() => page.close().catch(() => {}), 120000);
  try {
    await page.goto(base + "/");
    const results = await page.evaluate(
      async ({ base, n, max }) => {
        const pdfjs = await import(base + "/pdfjs/build/pdf.mjs");
        pdfjs.GlobalWorkerOptions.workerSrc = base + "/pdfjs/build/pdf.worker.mjs";
        const out = [];
        const t0 = performance.now();
        let doc;
        try {
          const buf = await (await fetch(base + "/file/" + n)).arrayBuffer();
          doc = await pdfjs.getDocument({
            data: new Uint8Array(buf),
            cMapUrl: base + "/pdfjs/cmaps/",
            cMapPacked: true,
            standardFontDataUrl: base + "/pdfjs/standard_fonts/",
            iccUrl: base + "/pdfjs/iccs/",
            wasmUrl: base + "/pdfjs/wasm/",
            isEvalSupported: false,
          }).promise;
        } catch (e) {
          return [{ page: 0, status: "load: " + String(e && e.message ? e.message : e) }];
        }
        const loadMs = performance.now() - t0;
        for (let i = 1; i <= Math.min(max, doc.numPages); i++) {
          try {
            const p = await doc.getPage(i);
            const vp = p.getViewport({ scale: 1 });
            const canvas = document.createElement("canvas");
            canvas.width = Math.ceil(vp.width);
            canvas.height = Math.ceil(vp.height);
            const ctx = canvas.getContext("2d");
            ctx.fillStyle = "white";
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            const t = performance.now();
            await p.render({ canvasContext: ctx, viewport: vp }).promise;
            out.push({ page: i, pages: doc.numPages, w: canvas.width, h: canvas.height, ms: +(performance.now() - t).toFixed(1), load_ms: +loadMs.toFixed(1), status: "ok", png: canvas.toDataURL("image/png").split(",")[1] });
          } catch (e) {
            out.push({ page: i, status: "render: " + String(e && e.message ? e.message : e) });
          }
        }
        return out;
      },
      { base, n, max },
    );
    for (const r of results) {
      const { png, ...line } = r;
      if (png) fs.writeFileSync(`${out}/${stem}-${r.page}.png`, Buffer.from(png, "base64"));
      console.log(JSON.stringify({ pdf: stem, ...line }));
    }
  } catch (e) {
    console.log(JSON.stringify({ pdf: stem, page: 0, status: "harness: " + String(e.message).slice(0, 200) }));
  }
  clearTimeout(timeout);
  await page.context().close().catch(() => {});
}
await browser.close();
server.close();
