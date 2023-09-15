import { LoadContext, Plugin } from '@docusaurus/types'
import * as blogPluginExports from '@docusaurus/plugin-content-blog'
import type {
  PluginOptions,
  BlogContent,
} from '@docusaurus/plugin-content-blog'

const blogPlugin = blogPluginExports.default

async function blogPluginEnhanced(
  context: LoadContext,
  options: PluginOptions,
): Promise<Plugin<BlogContent>> {
  const blogPluginInstance = await blogPlugin(context as any, options)

  return {
    ...blogPluginInstance,
    async contentLoaded({ content, allContent, actions }) {
      // Create default plugin pages
      await blogPluginInstance.contentLoaded({ content, allContent, actions })

      // Create your additional pages
      const { blogPosts, blogTags } = content
      const { setGlobalData } = actions

      setGlobalData({
        blogs: blogPosts,
        tags: blogTags,
      })
    },
  }
}

module.exports = {
  ...blogPluginExports,
  default: blogPluginEnhanced,
}
