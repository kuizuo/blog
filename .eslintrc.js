module.exports = {
  extends: [
    'plugin:@docusaurus/recommended',
    'plugin:@typescript-eslint/recommended',
  ],
  plugins: ['@docusaurus', '@typescript-eslint'],
  parserOptions: {
    ecmaVersion: 7,
    sourceType: 'module',
  }
};
