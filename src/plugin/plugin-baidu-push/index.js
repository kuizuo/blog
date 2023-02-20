module.exports = function (context, options) {
  return {
    name: 'docusaurus-plugin-baidu-push',
    injectHtmlTags() {
      return {
        headTags: [
          {
            tagName: 'script',
            innerHTML: `
            (function(){
              var bp = document.createElement('script');
              var curProtocol = window.location.protocol.split(':')[0];
              if (curProtocol === 'https') {
                  bp.src = 'https://zz.bdstatic.com/linksubmit/push.js';
              }
              else {
                  bp.src = 'http://push.zhanzhang.baidu.com/push.js';
              }
              bp.defer = true;
              var s = document.getElementsByTagName("script")[0];
              s.parentNode.insertBefore(bp, s);
          })();
          `,
          },
        ],
      }
    },
  }
}
