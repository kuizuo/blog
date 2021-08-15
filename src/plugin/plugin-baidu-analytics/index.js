module.exports = function (context, options) {
  return {
    name: "docusaurus-baidu-analytics-plugin",
    injectHtmlTags() {
      return {
        headTags: [
          {
            tagName: "script",
            innerHTML: `
            var _hmt = _hmt || [];
            (function() {
              var hm = document.createElement("script");
              hm.src = "https://hm.baidu.com/hm.js?135f3e7db7162b348a790b8b00e07413";
              hm.defer = true;
              var s = document.getElementsByTagName("script")[0]; 
              s.parentNode.insertBefore(hm, s);
            })();
          `,
          },
          {
            tagName: "meta",
            attributes: {
              name: "baidu-site-verification",
              content: "IXU12YQUjF",
            },
          },
        ],
      };
    },
  };
};
