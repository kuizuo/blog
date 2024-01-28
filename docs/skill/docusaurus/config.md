---
id: docusaurus-config
slug: /docusaurus-config
title: 配置文件
authors: kuizuo
---

## docusaurus.config.ts

`docusaurus.config.ts` 位于你的网站的根目录，包含了你的站点的配置信息。

在这里可以修改 logo，站点名(title)，作者名，顶部的公告(announcementBar)，导航栏(navbar)，底部导航(footer)等等。

```typescript title='docusaurus.config.ts' icon='logos:docusaurus'
const config: Config = {
  title: '愧怍的小站',
  url: 'https://kuizuo.cn',
  baseUrl: '/',
  favicon: 'img/favicon.ico',
  organizationName: 'kuizuo',
  projectName: 'blog',
  themeConfig: {
    image: 'img/logo.png',
    metadata: [
      {
        name: 'keywords',
        content: '愧怍, kuizuo, blog, javascript, typescript, node, react, vue, web, 前端, 后端',
      },
    ],
    // ...
}

export default config
```

同时绝大部分的配置信息都可以放在这里，例如搜索(algolia)，评论(giscus)，社交链接(socials)等等。这些配置都可以通过docusaurus内置的hook(useThemeConfig、useDocusaurusContext)来获取。

完整的配置信息说明 [docusaurus.config.ts | Docusaurus](https://docusaurus.io/zh-CN/docs/api/docusaurus-config)

## sidebars.js

用于配置文档的侧边栏，例如本博客中的[技术笔记](/docs/skill/)，[工具推荐](/docs/tools/)。侧边栏对应的每一项都是一个 markdown 文件，同时这些文件都存放在 docs 目录下，方便管理。

[侧边栏 | Docusaurus](https://docusaurus.io/zh-CN/docs/sidebar)

## 相关信息

### 基本信息

站点名和作者名只需要搜索 **愧怍** 或 **kuizuo** 便能找到关键位置，将其更改为你的便可。

### 关于我 页面

具体可在 `src/pages/about.mdx` 中查看与修改。

这里你可能需要展示你的技术栈，这里我推荐使用 [skillicons](https://skillicons.dev/) 来生成技术栈的图标，就如下面这样

[![My Skills](https://skillicons.dev/icons?i=ts,nodejs,vue,nuxt,react,nextjs,tailwind,nestjs,prisma,postgres,redis,supabase,rust,wasm,vscode)](https://skillicons.dev)

而 github 的状态信息使用[GitHub Profile Summary Cards](https://github-profile-summary-cards.vercel.app/demo.html) 或 [github-stats](https://github.com/jstrieb/github-stats) ，这里我选用 github-stats 因为带有动画，但需要图片需要自行构建。

![](https://raw.githubusercontent.com/kuizuo/github-stats/master/generated/overview.svg#gh-light-mode-only)

![](https://raw.githubusercontent.com/kuizuo/github-stats/master/generated/languages.svg#gh-light-mode-only)

### 友链、导航、项目 页面

这三个页面是通过 [plugin-content-pages](https://docusaurus.io/zh-CN/docs/api/plugins/@docusaurus/plugin-content-pages) 实现自定义页面的，如果想了解页面的实现可以看[自定义页面](/docs/docusaurus-style#自定义页面)

这里你主要关注数据部分，数据都存放至根文件夹 `/data` 下，并使用 ts 用作类型提示。这些数据最终会在这些页面中渲染，你只需要根据符合的类型定义所要展示的数据，访问对应页面就能查看到效果。

### 社交链接

只需要在 `data/social.ts` 中修改 social 对象即可。

内置了以下主流的可供选择的几个社交账号。

```typescript title='social.ts' icon='logos:typescript-icon'
export type Social = {
  github?: string
  twitter?: string
  juejin?: string
  qq?: string
  wx?: string
  cloudmusic?: string
  zhihu?: string
  email?: string
  discord?: string
}
```

## 其他配置

可能还需要配置下 giscus 评论，搜索，站点统计等等，这些会放在[插件](/docs/docusaurus-plugin)中细讲。
