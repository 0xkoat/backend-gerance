import eslint from '@eslint/js';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['eslint.config.mjs'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  eslintPluginPrettierRecommended,
  {
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
      sourceType: 'commonjs',
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-floating-promises': 'warn',
      '@typescript-eslint/no-unsafe-argument': 'warn',
      "prettier/prettier": ["error", { endOfLine: "auto" }],
      // The `const { hashedPassword, ...safe } = user` pattern — used
      // throughout auth/users/tenants to strip the hash before a response
      // body goes out — deliberately never reads the destructured binding.
      // A leading underscore marks that as intentional instead of every
      // call site needing its own eslint-disable comment.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { varsIgnorePattern: '^_', argsIgnorePattern: '^_' },
      ],
    },
  },
  {
    // Type-aware `no-unsafe-*` rules fight Jest's own type defs here, not
    // real bugs: `expect.any(...)`/`expect.objectContaining(...)` are
    // typed `any` by @types/jest (there's no way for them to know what
    // you're matching against ahead of time), so asserting against a
    // realistically-shaped mock call trips "unsafe assignment" on every
    // matcher, in every spec file, for a value that was never meant to be
    // fully typed. Scoped to test files only — application source code
    // keeps the full recommendedTypeChecked ruleset above.
    files: ['**/*.spec.ts', 'test/**/*.e2e-spec.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
    },
  },
);
