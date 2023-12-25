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
  titleDelimiter: '-',
  url: 'https://kuizuo.cn',
  baseUrl: '/',
  favicon: 'img/favicon.ico',
  organizationName: 'kuizuo',
  projectName: 'blog',
  tagline: '记录所学知识，领略编程之美',
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

站点名和作者名只需要搜索 **愧怍** 便能找到关键位置

### 关于我

具体可在 `src/pages/about.mdx` 中查看与修改。

其中技术栈的图标使用 [Shields.io](https://shields.io/) 生成，github 的状态信息使用[GitHub Profile Summary Cards](https://github-profile-summary-cards.vercel.app/demo.html)生成

所要做的就是将 username 替换成你的 github 名即可。

### 社交链接

只需要在 `docusaurus.config.ts` 中修改 socials 属性，替换成你的即可。

```typescript title='docusaurus.config.ts' icon='logos:docusaurus'
socials: {
  github: 'https://github.com/kuizuo',
  twitter: 'https://twitter.com/kuizuo',
  juejin: 'https://juejin.cn/user/1565318510545901',
  csdn: 'https://blog.csdn.net/kuizuo12',
  qq: 'https://wpa.qq.com/msgrd?v=3&amp;uin=911993023&amp;site=qq',
  cloudmusic: 'https://music.163.com/#/user/home?id=1333010742',
}
```

如果你还有其他社交链接，可以在这里添加对应的链接，然后在 `src/components/Hero.index.tsx` 中的 SocialLinks 组件中来配置新增或者删除社交链接图标。

### 友链、导航、项目

这里你需要关注数据部分，如果想了解页面的实现可以看[自定义页面](/docs/docusaurus-style#自定义页面)

数据部分存放在根目录 `/data` 下，并使用 ts 用作类型提示。这些数据最终会在这些页面中渲染，你只需要根据符合的类型定义所要展示的数据，访问对应页面就能查看到效果。

## 其他配置

可能还需要配置下 giscus 评论，搜索，站点统计等等，这些会放在[插件](/docs/docusaurus-plugin)中细讲。
