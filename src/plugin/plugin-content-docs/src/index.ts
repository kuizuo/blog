import {LoadContext, Plugin} from '@docusaurus/types';
import * as docsPluginExports from '@docusaurus/plugin-content-docs';
import type {
  PluginOptions,
  PropTagsListPage,
} from '@docusaurus/plugin-content-docs';

import type {LoadedContent} from './types';
import {getVersionTags} from './tags';

const docsPlugin = docsPluginExports.default;

async function docsPluginEnhanced(
  context: LoadContext,
  options: PluginOptions,
): Promise<Plugin<LoadedContent>> {
  const docsPluginInstance: any = await docsPlugin(context, options);

  return {
    name: 'docusaurus-plugin-content-docs-enhanced',
    async loadContent() {
      return await docsPluginInstance.loadContent();
    },
    async contentLoaded({content, actions}) {
      // Create default plugin pages
      // await docsPluginInstance.contentLoaded({ content, actions })

      // Create your additional pages
      const {loadedVersions} = content;
      const {setGlobalData} = actions;

      const versionTags = getVersionTags(loadedVersions[0].docs);
      const tagsProp: PropTagsListPage['tags'] = Object.values(versionTags).map(
        (tagValue) => ({
          label: tagValue.label,
          permalink: tagValue.permalink,
          count: tagValue.docIds.length,
        }),
      );

      if (tagsProp.length > 0) {
        setGlobalData({
          tags: tagsProp,
        });
      }
    },
  };
}

module.exports = {
  ...docsPluginExports,
  default: docsPluginEnhanced,
};
