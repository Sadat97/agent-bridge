import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/test/**/*.test.ts'],
    // Each relay test file creates its own database, so files can run in parallel.
    testTimeout: 20_000,
    hookTimeout: 30_000,
  },
});
