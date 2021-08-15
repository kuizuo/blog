module.exports = function (context, options) {
  return {
    name: "plugin-onesignal-push",
    injectHtmlTags() {
      return {
        headTags: [
          {
            tagName: "script",
            attributes: {
              src: "https://cdn.onesignal.com/sdks/OneSignalSDK.js",
              async: ""
            }
          },
          {
            tagName: "script",
            innerHTML: `
            window.OneSignal = window.OneSignal || [];
            OneSignal.push(function() {
              OneSignal.init({
                appId: "6391e77e-13e2-440e-aea0-fe760113a4d3",
                notifyButton: {
                  enable: true,
                },
              });
            });
          `,
          },
          
        ],
      };
    },
  };
};
