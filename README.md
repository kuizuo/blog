<h2 align="center">
  <p align="center">个人博客</p>
  <a href="https://kuizuo.cn">🖥 Online Preview</a>
</h2>

## Introduction

基于[🦖Docusaurus](https://docusaurus.io/)构建的个人博客

记录所学知识，领略编程之美

在这里你能了解到各类实战开发的所遇到的问题，帮助你在学习的过程了解最新的技术栈，并希望我的个人经历对你有所启发。

## Try it

https://stackblitz.com/github/kuizuo/blog

## Install

```sh
git clone https://github.com/kuizuo/blog.git
cd blog
yarn
yarn run start
```

## Build

```sh
npm build
```

## Catalogue

```tree
├── blog                           
│   ├── first-blog.md              # 博客文件
├── docs                           
│   └── doc1.md                    # 文档             
├── i18n                           # 国际化
├── src
│   ├── components                 # 自定义组件
│   ├── css                        # 自定义 CSS
│   ├── data                       # 项目/导航/友链数据
│   ├── pages                      # 自定义页面
│   ├── plugin                     # 自定义插件
│   └── theme                      # 自定义主题
├── static                         # 静态资源文件
│   ├── icons                      # 公用图标
│   ├── img                        # 公用图片（以及遗留的博客图片）
├── docusaurus.config.js           # 站点的配置信息
├── sidebars.js                    # 文档的侧边栏
├── package.json
├── tsconfig.json
└── yarn.lock
```

## Usage

在blog或docs目录下创建markdown文件，详情 -> [创建文档](https://docusaurus.io/zh-CN/docs/create-doc)  [新建帖子](https://docusaurus.io/zh-CN/docs/blog#adding-posts)



## License

[MIT licensed](https://github.com/kuizuo/blog/blob/main/LICENSE).
