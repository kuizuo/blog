---
slug: electron-vue3-development-environment
title: 搭建Electron+Vue3开发环境
date: 2022-03-17
authors: kuizuo
tags: [electron, vue, vite]
keywords: [electron, vue, vite]
description: 搭建 Electron Vue3 的开发环境，用于编写跨平台应用
---

![image-20220316204205165](https://img.kuizuo.cn/image-20220316204205165.png)

之前用 electron-vue 写过一个半成品的桌面端应用，但是是基于 Vue2 的，最近又想重写点桌面端应用，想要上 Vue3+TypeScript，于是便有了这篇文章总结下具体的搭建过程。

<!-- truncate -->

## Vue Cli

Vue CLI 有一个插件`vue-cli-plugin-electron-builder`，可以非常方便的搭建 electron 环境。

```sh
npm i @vue/cli -g
```

```sh
vue create my-app
```

根据自己项目的需求选择对应的依赖（例如 Babel，TS，Vuex 等等）

```sh
Vue CLI v5.0.3
? Please pick a preset: Manually select features
? Check the features needed for your project: Babel, TS, Vuex, CSS Pre-processors, Linter
? Choose a version of Vue.js that you want to start the project with 3.x
? Use class-style component syntax? Yes
? Use Babel alongside TypeScript (required for modern mode, auto-detected polyfills, transpiling JSX)? Yes
? Pick a CSS pre-processor (PostCSS, Autoprefixer and CSS Modules are supported by default): Sass/SCSS (with dart-sass)
? Pick a linter / formatter config: Prettier
? Pick additional lint features: Lint on save
? Where do you prefer placing config for Babel, ESLint, etc.? In package.json
? Save this as a preset for future projects? No


Vue CLI v5.0.3
✨  Creating project in F:\Electron\my-app.
🗃  Initializing git repository...
⚙️  Installing CLI plugins. This might take a while...
```

### 安装 vue-cli-plugin-electron-builder

[Vue CLI Plugin Electron Builder (nklayman.github.io)](https://nklayman.github.io/vue-cli-plugin-electron-builder/)

```sh
cd my-app
vue add electron-builder
```

安装过程中会提示你选择 Electron 的版本，选择最新版本即可

### 启动项目

```sh
npm run electron:serve
```

参考文章：[Electron + Vue3 开发跨平台桌面应用【从项目搭建到打包完整过程】 - 掘金 (juejin.cn)](https://juejin.cn/post/6983843979133468708)

### 坑

```
error  in ./src/background.ts

Module build failed (from ./node_modules/ts-loader/index.js):
TypeError: loaderContext.getOptions is not a function
```

我测试的时候，`@vue/cli-plugin-typescript`版本为`~5.0.0`，就会导致编译类型出错，将 package.json 中改为`"@vue/cli-plugin-typescript": "~4.5.15"`，即可正常运行（但还是会有 DeprecationWarning）

## Vite

上面是使用 Vue Cli 脚手架进行开发，如果想上 Vite 的话，就需要用 Vite 来构建项目，然后安装 electron 的相关依赖。

这个不是作为重点，因为很多大佬都已经写了现成的模板，完全可以自行借鉴学习，就贴几个阅读过的几篇文章

[Vite + Vue 3 + electron + TypeScript - DEV Community](https://dev.to/brojenuel/vite-vue-3-electron-5h4o)

[2021 年最前卫的跨平台开发选择！vue3 + vite + electron - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/424202065)

### 现成的模板

均可在 github 上搜索到

- [vite-react-electron](https://github.com/caoxiemeihao/vite-react-electron) (推荐)

- [electron-vue-vite](https://github.com/caoxiemeihao/electron-vue-vite) (推荐)
- [vite-electron-builder](https://github.com/cawa-93/vite-electron-builder)

### electron-vite 脚手架（推荐）

当然也可以使用脚手架，可选择 React 与 Vue，实际上也就是创建上面的前两个模板

```sh
npm create electron-vite
```

## 现有项目使用 electron

TODO...

## 总结

因为 Electron 本质上还是一个浏览器，无论是 Vue 还是 React 开发也好，在传统网页开发的时候都有对应的调试地址，如http://127.0.0.1:3000，而electron的做法无非就是开启一个浏览器，然后和正常的网页开发一样，并提供桌面端的api使用。

目前社区两大 Vue+Electron 的脚手架主要是[electron-vue](https://github.com/SimulatedGREG/electron-vue)和[vue-cli-plugin-electron-builder](https://github.com/nklayman/vue-cli-plugin-electron-builder)，更多 electron 的开源项目都遵循着前者的项目结构，像上面的模板也就是。

以上就是我所使用 Vue3 来开发 Electron 的环境搭建过程，总体来说从 Electron 除了应用体积过大，对于前端开发者来说是非常友好的，既然环境配置完，那么现在就可以开始好好的编写桌面端应用了。
