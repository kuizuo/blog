import { LoadContext, Plugin } from '@docusaurus/types'
import * as blogPluginExports from '@docusaurus/plugin-content-blog'
import type { PluginOptions } from '@docusaurus/plugin-content-blog'
import { BlogContent } from './types'

// @ts-ignore
import { projects } from '../../../../data/project.js'

const blogPlugin = blogPluginExports.default

async function blogPluginEnhanced(
  context: LoadContext,
  options: PluginOptions,
): Promise<Plugin<BlogContent>> {
  const blogPluginInstance: any = await blogPlugin(context, options)

  return {
    ...blogPluginInstance,
    async contentLoaded({ content, actions }) {
      // Create default plugin pages
      await blogPluginInstance.contentLoaded({ content, actions })

      // Create your additional pages
      const { blogPosts, blogTags } = content
      const { setGlobalData } = actions

      setGlobalData({
        blogs: blogPosts,
        tags: blogTags,
        projects: projects,
      })
    },
  }
}

module.exports = {
  ...blogPluginExports,
  default: blogPluginEnhanced,
}
