import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["ts/**/*.test.ts", "ts/**/*.test.tsx", "scripts/**/*.test.mjs"],
    environment: "jsdom",
  },
});
