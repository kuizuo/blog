import path from 'node:path'
import { fileURLToPath } from 'node:url'
import stylistic from '@stylistic/eslint-plugin'
import react from 'eslint-plugin-react'
import tailwind from 'eslint-plugin-tailwindcss'
import ts from 'typescript-eslint'

const dirname = path.dirname(fileURLToPath(import.meta.url))
const tailwindCssPath = path.join(dirname, 'src/css/custom.css')

export default [
  {
    ignores: ['.docusaurus', 'build'],
  },
  {
    settings: {
      tailwindcss: {
        config: tailwindCssPath,
      },
    },
  },
  stylistic.configs['recommended-flat'],
  ...ts.configs.recommended,
  ...tailwind.configs['flat/recommended'],
  {
    files: ['**/*.ts', '**/*.tsx'],
    plugins: {
      react: react,
    },
    rules: {
      ...react.configs['jsx-runtime'].rules,

      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-empty-object-type': 'off',
      '@typescript-eslint/no-explicit-any': 'off',

      'tailwindcss/no-custom-classname': 'off',
    },
  },
]
