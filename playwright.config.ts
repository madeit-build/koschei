import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'e2e',
  timeout: 30_000,
  use: { baseURL: 'http://localhost:4780', browserName: 'chromium' },
  webServer: { command: 'npm run build && node demo/serve.ts', port: 4780, reuseExistingServer: false, timeout: 60_000 },
});
