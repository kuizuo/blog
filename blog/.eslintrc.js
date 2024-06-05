module.exports = {
  parserOptions: {
    ecmaVersion: 7,
    sourceType: 'module',
  },
  plugins: ['@docusaurus', '@typescript-eslint'],
  extends: [
    'plugin:@docusaurus/recommended',
    'plugin:@typescript-eslint/recommended',
  ],
  rules: {
    '@typescript-eslint/no-unused-vars': 'off',
    "@typescript-eslint/no-explicit-any": "error"
  }
}
