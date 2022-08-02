module.exports = {
  extends: ['eslint:recommended', 'plugin:@docusaurus/recommended', 'plugin:@typescript-eslint/recommended', 'prettier',],
  plugins: ['@docusaurus', '@typescript-eslint'],
  parserOptions: {
    "ecmaVersion": 7,
    "sourceType": "module"
  }
};