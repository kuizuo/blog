module.exports = {
  presets: [
    require.resolve('@docusaurus/core/lib/babel/preset'),
    [
      "@babel/preset-react",
      { "runtime": "automatic", "importSource": "@emotion/react" }
    ]
  ],
  plugins: ["@emotion/babel-plugin"],
}
