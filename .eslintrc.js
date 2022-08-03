module.exports = {
  extends: ['plugin:@docusaurus/recommended', 'plugin:@typescript-eslint/recommended', 'prettier',],
  plugins: ['@docusaurus', '@typescript-eslint', '@typescript-eslint/parser',],
  parserOptions: {
    "ecmaVersion": 7,
    "sourceType": "module"
  }
};

