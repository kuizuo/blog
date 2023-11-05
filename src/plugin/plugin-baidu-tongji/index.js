module.exports = function (context, options) {
  return {
    name: 'docusaurus-plugin-baidu-tongji',
    injectHtmlTags() {
      if (process.env.NODE_ENV === 'development') {
        return {}
      }

      return {
        headTags: [
          {
            tagName: 'script',
            innerHTML: `
            var _hmt = _hmt || [];
            (function() {
              var hm = document.createElement("script");
              hm.src = "https://hm.baidu.com/hm.js?c9a3849aa75f9c4a4e65f846cd1a5155";
              hm.defer = true;
              var s = document.getElementsByTagName("script")[0];
              s.parentNode.insertBefore(hm, s);
            })();
          `,
          },
          {
            tagName: 'meta',
            attributes: {
              name: 'baidu-site-verification',
              content: 'code-rqLUw5reVS',
            },
          },
        ],
      }
    },
  }
}
