// node hayro-wasm.mjs LIST MAXPAGES: hayro compiled to wasm (renderPage), run in Chromium over the first
// MAXPAGES pages of each PDF named in LIST; one JSON line per page: ms, size, wasm memory after, or failure.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";

const root = process.env.EXAV_VIEWER_DIR ?? path.resolve(import.meta.dirname, "../../crates/exav-viewer");
const require = createRequire(root + "/package.json");
const { chromium } = require("playwright");
// wasm-bindgen's --target web output of hayro-wasm, with hayro_wasm_bg.opt.wasm made by wasm-opt.
const pkg = process.env.HAYRO_WASM_PKG ?? path.resolve(import.meta.dirname, "hayro-wasm/pkg");
const [list, maxArg] = process.argv.slice(2);
const max = Number(maxArg);
const files = fs.readFileSync(list, "utf8").split("\n").filter(Boolean);

const server = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url.split("?")[0]);
  let file;
  if (url === "/") {
    res.setHeader("content-type", "text/html");
    return res.end("<!doctype html><meta charset=utf-8><body>");
  }
  if (url.startsWith("/pkg/")) file = path.join(pkg, url.slice(5));
  else if (url.startsWith("/file/")) file = files[Number(url.slice(6))];
  else return res.writeHead(404).end();
  fs.readFile(file, (e, d) => {
    if (e) return res.writeHead(404).end();
    res.setHeader("content-type", file.endsWith(".js") ? "text/javascript" : file.endsWith(".wasm") ? "application/wasm" : "application/octet-stream");
    res.end(d);
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
for (let n = 0; n < files.length; n++) {
  const stem = path.basename(files[n], path.extname(files[n]));
  const page = await (await browser.newContext()).newPage();
  const timeout = setTimeout(() => page.close().catch(() => {}), 150000);
  try {
    await page.goto(base + "/");
    const results = await page.evaluate(
      async ({ base, n, max }) => {
        const m = await import(base + "/pkg/hayro_wasm.js");
        const wasm = await m.default({ module_or_path: base + "/pkg/hayro_wasm_bg.opt.wasm" });
        const buf = new Uint8Array(await (await fetch(base + "/file/" + n)).arrayBuffer());
        let count;
        try {
          count = m.pageCount(buf);
        } catch (e) {
          return [{ page: 0, status: "load: " + String(e && e.message ? e.message : e) }];
        }
        const out = [];
        for (let i = 0; i < Math.min(max, count); i++) {
          const t = performance.now();
          try {
            const r = m.renderPage(buf, i);
            const v = new DataView(r.buffer, r.byteOffset);
            out.push({ page: i + 1, pages: count, w: v.getUint32(0, true), h: v.getUint32(4, true), ms: +(performance.now() - t).toFixed(1), mem: wasm.memory.buffer.byteLength, status: "ok" });
          } catch (e) {
            out.push({ page: i + 1, status: "render: " + String(e && e.message ? e.message : e).slice(0, 100) });
            break;
          }
        }
        return out;
      },
      { base, n, max },
    );
    for (const r of results) console.log(JSON.stringify({ pdf: stem, ...r }));
  } catch (e) {
    console.log(JSON.stringify({ pdf: stem, page: 0, status: "harness: " + String(e.message).slice(0, 120) }));
  }
  clearTimeout(timeout);
  await page.context().close().catch(() => {});
}
await browser.close();
server.close();
