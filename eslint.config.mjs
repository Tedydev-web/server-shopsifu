import eslintConfigPrettier from 'eslint-config-prettier'
import tsEsLintPlugin from '@typescript-eslint/eslint-plugin'
import tsParser from '@typescript-eslint/parser'
import tsEslint from 'typescript-eslint'

const rules = tsEslint.configs.recommended
  .map((config) => config.rules)
  .filter((rules) => rules !== undefined)
  .reduce((a, b) => ({ ...b, ...a }), {})

export default [
  eslintConfigPrettier,
  {
    ignores: [
      '.github/*',
      '.husky/*',
      'coverage/*',
      'dist/*',
      'docs/*',
      'node_modules/*',
      '**/**/*.json',
      'src/shared/languages/generated/i18n.generated.ts'
    ]
  },
  {
    name: 'ts/default',
    files: ['src/**/*.ts'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parser: tsParser,
      parserOptions: {
        project: 'tsconfig.json',
        tsconfigRootDir: '.'
      }
    },
    linterOptions: {
      noInlineConfig: true,
      reportUnusedDisableDirectives: true
    },
    plugins: {
      '@typescript-eslint': tsEsLintPlugin
    },
    rules: {
      ...rules,
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-namespace': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          args: 'all',
          argsIgnorePattern: '^_',
          caughtErrors: 'all',
          caughtErrorsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          ignoreRestSiblings: true
        }
      ]
    }
  },
  {
    name: 'ts/test',
    files: ['test/**/*.spec.ts'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parser: tsParser,
      parserOptions: {
        project: 'tsconfig.json',
        tsconfigRootDir: '.'
      }
    },
    linterOptions: {
      noInlineConfig: false,
      reportUnusedDisableDirectives: true
    },
    plugins: {
      '@typescript-eslint': tsEsLintPlugin
    },
    rules: {
      ...rules,
      '@typescript-eslint/no-explicit-any': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          args: 'all',
          argsIgnorePattern: '^_',
          caughtErrors: 'all',
          caughtErrorsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          ignoreRestSiblings: true
        }
      ]
    }
  }
]
