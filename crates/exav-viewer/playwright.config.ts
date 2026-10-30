import { fileURLToPath } from "node:url";

import { defineConfig } from "@playwright/test";

// Against the demo as built for production (`npm run demo:build`): the
// package from dist/, through a host's bundler, as npm would ship it.
// E2E_BASE_URL points the tests at a demo served elsewhere, under any base
// ("http://localhost:8000/viewer/demo/"); without it, `vite preview` serves it.
const external = process.env.E2E_BASE_URL;

// Text without subpixel antialiasing on Linux, and the generic families the
// Liberation fonts (e2e/fonts.conf), in every engine.
const fonts = { ...process.env, FONTCONFIG_FILE: fileURLToPath(new URL("./e2e/fonts.conf", import.meta.url)) };

export default defineConfig({
  testDir: "./e2e",
  // The large files the delivery tests open.
  globalSetup: "./e2e/delivery-setup.ts",
  timeout: 60_000,
  expect: { timeout: 20_000 },
  // One browser at a time: each engine is a worker and a WebGL context.
  workers: 1,
  use: {
    // 127.0.0.1, where the demo's frame policy names it (demo/vite.config.ts):
    // "localhost" is then another origin on the same server (frame.spec.ts).
    baseURL: external ?? "http://127.0.0.1:4317/",
    headless: true,
    viewport: { width: 1280, height: 800 },
    screenshot: "only-on-failure",
  },
  ...(!external && {
    webServer: {
      command: "npx vite preview --config demo/vite.config.ts --host 127.0.0.1 --port 4317 --strictPort",
      url: "http://127.0.0.1:4317/",
      reuseExistingServer: !process.env.CI,
    },
  }),
  projects: [
    {
      name: "chromium",
      // WebGL in a headless Chromium without a GPU.
      use: {
        browserName: "chromium",
        launchOptions: { args: ["--use-angle=swiftshader", "--enable-unsafe-swiftshader"], env: fonts },
      },
    },
    // The sandboxed frame's guarantees, text selection, the converted Office
    // formats and the pictures of Office documents in the other engines (in
    // WebKit, in the page only: it refuses the workers of a frame served
    // isolated). Headless Firefox here has no WebGL, so the model pictures run
    // in WebKit only. The CAD specs stay on Chromium: WebKit on Linux shows
    // nothing for a WebGL canvas made with `antialias: false`, which CAD
    // drawings need (docs/BACKLOG.md, "Cross-browser").
    { name: "firefox", testMatch: /(frame|delivery|selection|converted|office-raster)\.spec\.ts/, use: { browserName: "firefox", launchOptions: { env: fonts } } },
    { name: "webkit", testMatch: /(frame|delivery|selection|converted|office-raster|model-raster)\.spec\.ts/, use: { browserName: "webkit", launchOptions: { env: fonts } } },
  ],
});
