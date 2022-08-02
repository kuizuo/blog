'use strict';
var __awaiter =
  (this && this.__awaiter) ||
  function (thisArg, _arguments, P, generator) {
    function adopt(value) {
      return value instanceof P
        ? value
        : new P(function (resolve) {
            resolve(value);
          });
    }
    return new (P || (P = Promise))(function (resolve, reject) {
      function fulfilled(value) {
        try {
          step(generator.next(value));
        } catch (e) {
          reject(e);
        }
      }
      function rejected(value) {
        try {
          step(generator['throw'](value));
        } catch (e) {
          reject(e);
        }
      }
      function step(result) {
        result.done
          ? resolve(result.value)
          : adopt(result.value).then(fulfilled, rejected);
      }
      step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
  };
Object.defineProperty(exports, '__esModule', {value: true});
const docsPluginExports = require('@docusaurus/plugin-content-docs');
const tags_1 = require('./tags');
const docsPlugin = docsPluginExports.default;
function docsPluginEnhanced(context, options) {
  return __awaiter(this, void 0, void 0, function* () {
    const docsPluginInstance = yield docsPlugin(context, options);
    return {
      name: 'docusaurus-plugin-content-docs-enhanced',
      loadContent() {
        return __awaiter(this, void 0, void 0, function* () {
          return yield docsPluginInstance.loadContent();
        });
      },
      contentLoaded({content, actions}) {
        return __awaiter(this, void 0, void 0, function* () {
          // Create default plugin pages
          // await docsPluginInstance.contentLoaded({ content, actions })
          // Create your additional pages
          const {loadedVersions} = content;
          const {setGlobalData} = actions;
          const versionTags = (0, tags_1.getVersionTags)(
            loadedVersions[0].docs,
          );
          const tagsProp = Object.values(versionTags).map((tagValue) => ({
            label: tagValue.label,
            permalink: tagValue.permalink,
            count: tagValue.docIds.length,
          }));
          if (tagsProp.length > 0) {
            setGlobalData({
              tags: tagsProp,
            });
          }
        });
      },
    };
  });
}
module.exports = Object.assign(Object.assign({}, docsPluginExports), {
  default: docsPluginEnhanced,
});
