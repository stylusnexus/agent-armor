import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  test: {
    // packages/ml has its own dependencies and its own CI job (ml-package);
    // the root install does not have them.
    exclude: [...configDefaults.exclude, 'packages/**'],
  },
});
