"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const blogPluginExports = (0, tslib_1.__importStar)(require("@docusaurus/plugin-content-blog"));
const blogPlugin = blogPluginExports.default;
function blogPluginEnhanced(context, options) {
    return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
        const blogPluginInstance = yield blogPlugin(context, options);
        return Object.assign(Object.assign({}, blogPluginInstance), { contentLoaded({ content, actions }) {
                return (0, tslib_1.__awaiter)(this, void 0, void 0, function* () {
                    // Create default plugin pages
                    yield blogPluginInstance.contentLoaded({ content, actions });
                    // Create your additional pages
                    const { blogPosts, blogTags } = content;
                    const { setGlobalData } = actions;
                    setGlobalData({
                        // blogs: blogPosts,
                        tags: blogTags,
                        projects: [],
                    });
                });
            } });
    });
}
module.exports = Object.assign(Object.assign({}, blogPluginExports), { default: blogPluginEnhanced });
