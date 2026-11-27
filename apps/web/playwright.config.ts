import { defineConfig } from "@playwright/test";
import { testWorkspaceKey } from "./tests/auth-fixture";
export default defineConfig({
  testDir: "./tests",
  timeout: 30000,
  use: { baseURL: "http://127.0.0.1:3100", headless: true, trace: "retain-on-failure" },
  reporter: [["list"], ["html", { open: "never" }]],
  webServer: [
    {
      command:
        "uv run --project ../.. --locked --extra api uvicorn traceward_api.app:app --host 127.0.0.1 --port 8100 --no-access-log",
      url: "http://127.0.0.1:8100/api/v1/health",
      timeout: 60000,
    },
    {
      command: "bun run start --port 3100",
      env: {
        TRACEWARD_API_URL: "http://127.0.0.1:8100",
        TRACEWARD_WORKSPACE_KEY: testWorkspaceKey,
        NEXT_TELEMETRY_DISABLED: "1",
      },
      url: "http://127.0.0.1:3100",
      timeout: 60000,
    },
  ],
});
