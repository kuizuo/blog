module.exports = function (context, options) {
  return {
    name: "docusaurus-latest-docs-plugin",
    async loadContent() {
      console.log(context);
      return 1 + Math.floor(Math.random() * 10);
    },
    async contentLoaded({ content, actions }) {
      console.log(content);
      console.log("===========");
    },
  };
};
