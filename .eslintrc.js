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
}
