import stylistic from '@stylistic/eslint-plugin'
import reactPlugin from 'eslint-plugin-react'
import tailwind from 'eslint-plugin-tailwindcss'
import ts from 'typescript-eslint'

export default [
  {
    ignores: ['.docusaurus', 'build'],
  },
  stylistic.configs['recommended-flat'],
  ...ts.configs.recommended,
  ...tailwind.configs['flat/recommended'],
  {
    files: ['**/*.ts', '**/*.tsx'],
    plugins: {
      react: reactPlugin,
    },
    rules: {
      ...reactPlugin.configs['jsx-runtime'].rules,

      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-empty-object-type': 'off',
      '@typescript-eslint/no-explicit-any': 'off',

      'tailwindcss/no-custom-classname': 'off',
    },
  },
]
