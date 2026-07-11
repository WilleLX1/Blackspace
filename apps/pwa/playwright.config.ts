import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  webServer: process.env.BLACKSPACE_WEB_URL ? undefined : {
    command: "npx --yes pnpm@10.2.1 dev",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: true,
  },
  use: {
    baseURL: process.env.BLACKSPACE_WEB_URL ?? "http://127.0.0.1:5173",
    trace: "retain-on-failure",
  },
  reporter: "line",
});
