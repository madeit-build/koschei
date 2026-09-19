import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // e2e/ holds Playwright specs (run via `npm run e2e`), not vitest ones; without this,
    // vitest's default *.spec.ts glob picks them up and errors on the Playwright `test` global.
    exclude: ['**/node_modules/**', '**/dist/**', 'e2e/**'],
  },
});
