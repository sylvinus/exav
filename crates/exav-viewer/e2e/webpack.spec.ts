// The package as npm ships it, through a bundler other than Vite and with no
// configuration: the tarball `npm pack` makes, installed into a fresh
// project, built by webpack 5, served as static files. What it must find on
// its own is what the package reaches with `new URL(..., import.meta.url)`:
// the workers, both wasm modules, the fonts.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";
import webpack from "webpack";

import { decodePng, find } from "./pixels.js";
import { SAMPLES } from "./samples.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const samples = SAMPLES;
const TYPES: Record<string, string> = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".css": "text/css", ".woff2": "font/woff2" };

let dir = "";
let server: http.Server;
let base = "";

test.beforeAll(async () => {
  test.setTimeout(180_000);
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "exav-viewer-webpack-"));
  const tarball = execFileSync("npm", ["pack", "--ignore-scripts", "--silent", "--pack-destination", dir], { cwd: root, encoding: "utf8" }).trim().split("\n").pop()!;
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "host", private: true, dependencies: { "@exav/viewer": `file:./${tarball}` } }));
  // The package has no dependencies of its own, and its peers are optional:
  // nothing is fetched.
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--offline"], { cwd: dir, stdio: "ignore" });

  fs.mkdirSync(path.join(dir, "src"));
  fs.writeFileSync(
    path.join(dir, "src", "index.js"),
    `import "@exav/viewer/styles.css";
import { createViewer } from "@exav/viewer";
import { dwg } from "@exav/viewer/cad";
import { image } from "@exav/viewer/image";
const params = new URLSearchParams(location.search);
const budget = params.get("maxPrimitives");
const expand = params.get("maxDecompressedBytes");
const cad = {};
if (budget) cad.maxPrimitives = Number(budget);
if (expand) cad.maxDecompressedBytes = Number(expand);
const viewer = createViewer({ plugins: [dwg(cad), image({ wasmDecoders: true })] });
const name = params.get("file");
const session = viewer.mount(document.getElementById("host"), { id: name, name, source: { url: "./" + name } });
session.status.subscribe((s) => (document.body.dataset.phase = s.phase));
const showWarnings = (w) => (document.body.dataset.warnings = w.map((x) => x.key).join(","));
session.controllers.subscribe((c) => {
  if (!c.warnings) return;
  showWarnings(c.warnings.get());
  c.warnings.subscribe(showWarnings);
});
`,
  );
  const out = path.join(dir, "dist");
  const stats = await new Promise<webpack.Stats>((resolve, reject) =>
    webpack(
      {
        mode: "production",
        context: dir,
        entry: "./src/index.js",
        output: { path: out },
        // The stylesheet, as a file beside the bundle: no loader is the
        // package's to require.
        module: { rules: [{ test: /\.css$/, type: "asset/resource", generator: { filename: "styles.css" } }] },
        performance: { hints: false },
      },
      (error, result) => (error || !result ? reject(error) : resolve(result)),
    ),
  );
  expect(stats.hasErrors(), stats.toString("errors-only")).toBe(false);
  fs.writeFileSync(path.join(out, "index.html"), `<!doctype html><link rel="stylesheet" href="styles.css"><div id="host" style="width:800px;height:600px;position:relative"></div><script src="main.js"></script>`);
  for (const f of ["plan.dwg", "landscape.tif"]) fs.copyFileSync(path.join(samples, f), path.join(out, f));

  server = http.createServer((req, res) => {
    const file = path.join(out, decodeURIComponent((req.url ?? "/").split("?")[0]!).replace(/^\/$/, "/index.html"));
    if (!file.startsWith(out) || !fs.existsSync(file)) {
      res.statusCode = 404;
      res.end();
      return;
    }
    res.setHeader("Content-Type", TYPES[path.extname(file)] ?? "application/octet-stream");
    res.end(fs.readFileSync(file));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
});

test.afterAll(async () => {
  await new Promise((resolve) => server?.close(resolve));
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test("webpack, unconfigured, emits what a DWG needs and the plan is drawn whole", async ({ page }) => {
  await page.goto(`${base}?file=plan.dwg`);
  await expect(page.locator("body")).toHaveAttribute("data-phase", "ready");
  await expect
    .poll(async () => {
      const box = find(decodePng(await page.locator("#host").screenshot()), (r, g, b) => r < 90 && g < 90 && b < 90).box;
      return box ? Math.round((box.width / box.height) * 10) / 10 : 0;
    })
    .toBe(1.5);
});

// The engine counts what a budget leaves out; the view refits to what was
// drawn, so pixels cannot tell a part from the whole.
test("maxPrimitives reaches the engine: a small budget draws part of the plan and says so", async ({ page }) => {
  await page.goto(`${base}?file=plan.dwg`);
  await expect(page.locator("body")).toHaveAttribute("data-phase", "ready");
  await expect(page.locator("body")).toHaveAttribute("data-warnings", "");

  await page.goto(`${base}?file=plan.dwg&maxPrimitives=20`);
  await expect(page.locator("body")).toHaveAttribute("data-phase", "ready");
  await expect(page.locator("body")).toHaveAttribute("data-warnings", "scene_truncated");
});

// plan.dwg is a 2018 DWG: its compressed sections expand to some tens of
// kilobytes, past a limit of 1000 bytes and within the default.
test("maxDecompressedBytes reaches the engine: below what the plan's sections expand to, it is refused", async ({ page }) => {
  await page.goto(`${base}?file=plan.dwg&maxDecompressedBytes=1000000`);
  await expect(page.locator("body")).toHaveAttribute("data-phase", "ready");

  await page.goto(`${base}?file=plan.dwg&maxDecompressedBytes=1000`);
  await expect(page.locator("body")).toHaveAttribute("data-phase", "error");
});

test("webpack, unconfigured, emits the image decoders and a TIFF is drawn", async ({ page }) => {
  await page.goto(`${base}?file=landscape.tif`);
  await expect(page.locator("body")).toHaveAttribute("data-phase", "ready");
  await expect.poll(async () => find(decodePng(await page.locator("#host").screenshot()), (r, g, b) => r > 235 && g > 185 && g < 215 && b < 100).count).toBeGreaterThan(1000);
});
