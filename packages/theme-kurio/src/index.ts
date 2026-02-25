/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import type { Plugin } from '@docusaurus/types'

/**
 * Check if the optional @mermaid-js/layout-elk package is available.
 * It's an optional peer dependency because it's heavy and most Mermaid users
 * might not need it.
 */

export default async function themeKurio(): Promise<Plugin<void>> {
  return {
    name: 'docusaurus-theme-kurio',

    getThemePath() {
      return '../lib/theme'
    },
    getTypeScriptThemePath() {
      return '../src/theme'
    },

    configureWebpack(config, isServer, utils) {
      return {

      }
    },
  }
}

// export { validateThemeConfig } from './validateThemeConfig'
