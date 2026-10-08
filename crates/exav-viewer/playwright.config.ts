import { defineConfig } from "@playwright/test";

// Against the demo as built for production (`npm run demo:build`): the
// package from dist/, through a host's bundler, as npm would ship it.
// E2E_BASE_URL points the tests at a demo served elsewhere, under any base
// ("http://localhost:8000/viewer/demo/"); without it, `vite preview` serves it.
const external = process.env.E2E_BASE_URL;

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
      use: { browserName: "chromium", launchOptions: { args: ["--use-angle=swiftshader", "--enable-unsafe-swiftshader"] } },
    },
    // The sandboxed frame's guarantees, and text selection, in the other engines.
    { name: "firefox", testMatch: /(frame|delivery|selection)\.spec\.ts/, use: { browserName: "firefox" } },
    { name: "webkit", testMatch: /(frame|delivery|selection)\.spec\.ts/, use: { browserName: "webkit" } },
  ],
});
