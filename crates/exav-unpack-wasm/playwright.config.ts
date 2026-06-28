import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  use: {
    baseURL: 'http://localhost:3847',
    headless: true,
  },
  webServer: {
    command: 'python3 -m http.server 3847 --directory .',
    port: 3847,
    reuseExistingServer: true,
    cwd: '.',
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
  ],
});
