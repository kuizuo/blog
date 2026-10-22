<h2 align="center">
愧怍的个人博客
</h2>
<p align="center">
<a href="https://vercel.com/new/clone?repository-url=https://github.com/kuizuo/blog/tree/main&project-name=blog&repo-name=blog" rel="nofollow"><img src="https://vercel.com/button"></a>
<a href="https://app.netlify.com/start/deploy?repository=https://github.com/kuizuo/blog" rel="nofollow"><img src="https://www.netlify.com/img/deploy/button.svg"></a>
<a href="https://stackblitz.com/github/kuizuo/blog" rel="nofollow"><img src="https://developer.stackblitz.com/img/open_in_stackblitz.svg"></a>
</p>

## 👋 介绍

在这里我会分享各类技术栈所遇到问题与解决方案，带你了解最新的技术栈以及实际开发中如何应用，并希望我的开发经历对你有所启发。

如果你想要搭建一个类似的站点，可直接 [Fork](https://github.com/kuizuo/blog/fork) 本仓库使用，或者通过 [StackBlitz](https://stackblitz.com/github/kuizuo/blog) 在线运行本项目，通过 [Vercel](https://vercel.com/new/clone?repository-url=https://github.com/kuizuo/blog/tree/main&project-name=blog&repo-name=blog) 一键部署。

[![Deploy to Wasmer](https://img.shields.io/badge/Deploy%20to-Wasmer-171717?logo=wasmer&logoColor=white)](https://wasmer.io/apps/create?github=kuizuo%2Fblog)

也可以部署到 Wasmer Edge：本站通过 `pnpm build` 生成纯静态文件（输出目录 `build`）。上面的按钮导入的是本仓库，不会复制到你的 GitHub 账号；如需自定义，请先 Fork，再导入你自己的仓库。部署前记得修改 `data/site.ts` 中的 `url`，以及 `docusaurus.config.ts` 中的 Algolia、Giscus 和 Google Analytics（`gtag`）配置。

## ✨ 特性

- 🦖 **Docusaurus** - 基于 Docusaurus，提供强大的文档生成和博客功能
- ✍️ **Markdown** - 写作方便，Markdown
- 🎨 **Beautiful** - 整洁，美观，阅读体验优先
- 🖥️ **PWA** - 支持 PWA，可安装，离线可用
- 🌐 **i18n** - 支持国际化
- 💯 **SEO** - 搜索引擎优化，易于收录
- 📊 **谷歌分析** - 支持 Google Analytics
- 🔎 **全文搜索** - 支持 [Algolia DocSearch](https://github.com/algolia/docsearch)
- 🚀 **持续集成** - 支持 CI/CD，自动部署更新内容
- 🏞️ **首页视图** - 显示最新博客文章、项目展示，个人特点，技术栈等
- 🗃️ **博文视图** - 不同的博文视图，列表、宫格
- 🌈 **资源导航** - 收集并分享有用、有意思的资源
- 📦 **项目展示** - 展示你的项目，可用作于作品集

我的主题魔改实现：[Docusaurus 主题魔改](https://kuizuo.me/docs/docusaurus-guides)

## :wrench: 技术栈

- Docusaurus
- TailwindCSS
- Framer motion & magicui 

## 📊 目录结构

```bash
├── blog                           # 博客
│   ├── first-blog.md
├── docs                           # 文档/笔记
│   └── doc.md
├── data
│   ├── feature.tsx                # 特点
│   ├── friends.tsx                # 友链
│   ├── projects.tsx               # 项目
│   ├── skills.tsx                 # 技术栈
│   └── social.ts                  # 社交链接
├── i18n                           # 国际化
├── src
│   ├── components                 # 组件
│   ├── css                        # 自定义CSS
│   ├── pages                      # 自定义页面
│   ├── plugin                     # 自定义插件
│   └── theme                      # 自定义主题组件
├── static                         # 静态资源文件
│   └── img                        # 静态图片
├── docusaurus.config.ts           # 站点的配置信息
├── sidebars.ts                    # 文档的侧边栏
├── package.json
├── tsconfig.json
└── pnpm-lock.yaml
```

## 📥 运行

```bash
git clone https://github.com/kuizuo/blog.git
cd blog
pnpm install
pnpm start
```

构建

```bash
pnpm build
```

## 📷 截图

<img width="1471" alt="Live Demo" src="https://github.com/kuizuo/blog/blob/main/static/img/og.png?raw=true">

## 📝 许可证

[MIT](./LICENSE)
