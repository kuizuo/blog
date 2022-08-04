## 个人博客

<a href="https://kuizuo.cn">🖥 Online Preview</a>

## Introduction

基于[🦖Docusaurus](https://docusaurus.io/)构建的个人博客

在这里你能了解到各类实战开发的所遇到的问题，帮助你在学习的过程了解最新的技术栈，并希望我的个人经历对你有所启发。

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

```tree
├── blog                           
│   ├── first-blog.md              # 博客文件
├── docs                           
│   └── doc.md                     # 文档             
├── i18n                           # 国际化
├── src
│   ├── components                 # 组件
│   ├── css                        # 自定义CSS
│   ├── data                       # 项目/导航/友链数据
│   ├── pages                      # 自定义页面
│   ├── plugin                     # 自定义插件
│   └── theme                      # 自定义主题组件
├── static                         # 静态资源文件
│   ├── icons                      # 静态图标
│   ├── img                        # 静态图片
├── docusaurus.config.js           # 站点的配置信息
├── sidebars.js                    # 文档的侧边栏
├── package.json
├── tsconfig.json
└── yarn.lock
```

## License

[MIT licensed](https://github.com/kuizuo/blog/blob/main/LICENSE).
