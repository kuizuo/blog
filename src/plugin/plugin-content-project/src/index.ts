import { LoadContext, Plugin, PluginOptions } from '@docusaurus/types'

import { sortedProjects, type Project } from '../../../data/project'

function generateProjects(projectsPath?: string): Project[] {
  return sortedProjects
}

export default async function projectPlugin(context: LoadContext, options: PluginOptions): Promise<Plugin<any>> {
  return {
    name: 'docusaurus-plugin-content-project',
    async loadContent() {
      const projects = await generateProjects()
      return { projects }
    },
    async contentLoaded({ content, actions }) {
      const { projects } = content
      const { setGlobalData } = actions

      setGlobalData({
        projects: projects,
      })
    },
  }
}
