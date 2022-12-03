<h2 align="center">
愧怍的个人博客
</h2><br>

<pre align="center">
 Build with 🦖<a href="https://kuizuo.cn">Docusaurus</a> 
</pre>

<p align="center">
<br>
<a href="https://kuizuo.cn">🖥 Online Preview</a>
<br><br> 
<a href="https://vercel.com/new/clone?repository-url=https://github.com/kuizuo/blog/tree/main&project-name=blog&repo-name=blog" rel="nofollow"><img src="https://vercel.com/button"></a>
<a href="https://app.netlify.com/start/deploy?repository=https://github.com/kuizuo/blog" rel="nofollow"><img src="https://www.netlify.com/img/deploy/button.svg"></a>
<a href="https://stackblitz.com/github/kuizuo/blog" rel="nofollow"><img src="https://developer.stackblitz.com/img/open_in_stackblitz.svg"></a>
</p>

## Introduction

在这里我会分享各类技术栈所遇到问题与解决方案，带你了解最新的技术栈，以及在实际开发中如何应用，提升开发效率。

## Install

```sh
git clone https://github.com/kuizuo/blog.git
cd blog
yarn
yarn run start
```

## Build

```sh
yarn run build
```

## Catalogue

```bash
├── blog                           # 博客
│   ├── first-blog.md              
├── docs                           # 文档/笔记
│   └── doc.md                     
├── data                           # 项目/导航/友链数据
│   ├── friend.ts                  # 友链
│   ├── project.ts                 # 项目
│   └── website.ts                 # 导航
├── i18n                           # 国际化
├── src
│   ├── components                 # 组件
│   ├── css                        # 自定义CSS
│   ├── pages                      # 自定义页面
│   ├── plugin                     # 自定义插件
│   └── theme                      # 自定义主题组件
├── static                         # 静态资源文件
│   └── img                        # 静态图片
├── docusaurus.config.js           # 站点的配置信息
├── sidebars.js                    # 文档的侧边栏
├── package.json
├── tsconfig.json
└── yarn.lock
```

## My Change

[Docusaurus2 主题魔改](https://kuizuo.cn/docs/docusaurus-guides)

## License

[MIT](./LICENSE)
