const { normalizeUrl } = require('@docusaurus/utils');
const blogPluginExports = require('@docusaurus/plugin-content-blog')

const blogPlugin = blogPluginExports.default
async function blogPluginEnhanced(context, options) {
  const blogPluginInstance = await blogPlugin(context, options)

  const { siteConfig } = context
  const { baseUrl } = siteConfig

  const a = {
    ...blogPluginInstance,
    async contentLoaded(contentLoadedArgs) {
      // Create default plugin pages
      await blogPluginInstance.contentLoaded(contentLoadedArgs)

      // Create your additional pages
      const { content, actions } = contentLoadedArgs
      const { blogPosts, blogTags } = content
      const { setGlobalData } = actions
      setGlobalData({
        // blogs: blogPosts,
        tags: blogTags,
      });
    },
  }
  return a
} 0

module.exports = {
  ...blogPluginExports,
  default: blogPluginEnhanced,
}
