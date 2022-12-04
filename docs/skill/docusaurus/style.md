---
id: docusaurus-style
slug: /docusaurus-style
title: 样式与页面
authors: kuizuo
---

## [样式和布局](https://docusaurus.io/zh-CN/docs/styling-layout#styling-your-site-with-infima)

Docusaurus 网站是一个 React 单页应用。 你可以像一般的 React 应用一样给网站提供样式，想 tailwindCSS 与 组件库都是支持的。不过引入这些会带来一定的体积，因此我常用的是全局样式与 CSS 模块。

## 修改主题色

可以在 [这里](https://docusaurus.io/zh-CN/docs/styling-layout#styling-your-site-with-infima) 设置主色调与背景色来查看浅色与深色模式下的效果，例如我的主题色是 <font color="#12AFFA">#12AFFA</font>

`@docusaurus/preset-classic` 用 [Infima](https://infima.dev/) 作为底层样式框架。 Infima 提供了灵活的布局，以及常见的 UI 组件样式，适用于以内容为中心的网站（博客、文档、首页）。想要了解更多详情，请查看 [Infima 网站](https://infima.dev/)。

## 主页

因为设置了[仅博客模式](https://docusaurus.io/zh-CN/docs/blog#blog-only-mode)，没有专门编写的首页，而是将博文列表设置为首页。需要将 `src/pages/index.tsx` 文件给删除（或者改个名），否则会导致首页路径冲突。当然你也可以专门搞一个主页，就像 docusaurus 那样，然后跳转至博文列表页。

所以博客页面，也就是首页。但仅仅只有博客是远远不够的，所以便添加了 Hero 组件，也就是首次访问博客的样子。

主页右侧 SVG 背景文件地址: `src/components/Hero/img/hero_main.svg`, 插画来源于 [unDraw](https://undraw.co/illustrations)，在这个网站可以找到这类插画风格的背景。或者你可以找专门设计插画的人为你设计。

## 自定义页面

[友链](/friends)、[导航](/website)、[项目](/project)以及[关于我](/about)页面都在 `src/pages` 目录下定义，根据文件名映射对应路由。页面的创建可以查看 [创建页面 | Docusaurus](https://docusaurus.io/zh-CN/docs/creating-pages)
