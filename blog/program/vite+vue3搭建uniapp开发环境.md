---
slug: vite-vue3-build-uniapp-environment
title: vite+vue3搭建uniapp开发环境
date: 2022-03-27
authors: kuizuo
tags: [vue, vite, uniapp, develop]
keywords: [vue, vite, uniapp, develop]
description: 使用 vite vue3 搭建 uniapp 开发环境
---

![uniapp](https://img.kuizuo.cn/uniapp.png)

最近想搞个移动端或小程序的 Vue3 项目，所以选择跨端开发平台就显得十分重要。在业内主要有两个跨端开发平台，Taro 与 uniapp，但 uniapp 貌似对 vue3 的支持不是特别友好。所以让我在 Taro 和 uniapp 之间抉择了一段时间，最终还是尝试选择相对熟悉的 uniapp 来进行开发。

:::caution 前排提醒

目前 uniapp 对 Vue3 的支持还处于 alpha 版，即开发阶段，大概率是会遇到很多问题的。

:::

<!-- truncate -->

## 开发环境搭建

建议安装 HBuilderX，主要是 uni cli 在 APP 平台仅支持生成离线打包的 wgt 资源包，不支持云端打包生成 apk/ipa，并且也不便配置一些打包后的参数。

这里建议安装 Alpha 版，后文会说明缘由。

:::caution 注意

在 HBuilderX 正式版中是无法直接创建 Vue3 项目的，而 Alpha 版有 Vue2 和 3 可供选择，但创建的自带的模板大部分的写法还是 vue2 的写法（无 setup 语法糖），所以这时候要么改代码自建，要么使用官方所提供的 [Vue3 模板](https://uniapp.dcloud.io/worktile/CLI.html#%E5%88%9B%E5%BB%BA%E5%B7%A5%E7%A8%8B)

![image-20220327000608783](https://img.kuizuo.cn/image-20220327000608783.png)

:::

```sh
# 创建以 javascript 开发的工程
npx degit dcloudio/uni-preset-vue#vite my-vue3-project

# 创建以 typescript 开发的工程
npx degit dcloudio/uni-preset-vue#vite-ts my-vue3-project
```

当然，有可能会下载失败，可以直接访问 [gitee](https://gitee.com/dcloud/uni-preset-vue/repository/archive/vite-ts.zip)下载模板。

## 项目结构

```
|-- src
	|-- App.vue
	|-- env.d.ts
 	|-- main.ts
 	|-- manifest.json
  	|-- pages.json
 	|-- uni.scss
 	|-- pages
 	|   |-- index
 	|       |-- index.vue
  	|-- static
 		|-- logo.png
|-- index.html
|-- package-lock.json
|-- package.json
|-- postcss.config.js
|-- tsconfig.json
|-- vite.config.ts
```

下载完毕，开始安装依赖，接着就可以开始测试了。

## 运行编译

在运行之前，首先将**vuex**包给移除，不然将会有如下提示，总之就是不推荐使用的意思，而且要使用状态管理也推荐使用 pinia。所以执行 `yarn remove vuex` 吧

```
(node:26968) [DEP0148] DeprecationWarning: Use of deprecated folder mapping "./" in the "exports" field module resolution of the package at F:\Uniapp\my-vue3-project1\node_modules\vuex\package.json.
Update this package.json to use a subpath pattern like "./*".
```

### H5

运行编译都正常

### APP

使用`npm run dev:app`后就会发现，终端一直卡在如下界面无法继续。（后面测试发现，除了 H5 能正常运行，其他都会卡住）

```
编译器版本：3.4.3（vue3）
请注意运行模式下，因日志输出、sourcemap 以及未压缩源码等原因，性能和包体积，均不及发行模式
。
正在编译中...
vite v2.8.6 building for development...
DONE  Build complete. Watching for changes...
ready in 1554ms.
```

然后呢？？？

算了，就用 HBuilderX 的 cli 先运行到手机或模拟器，然后后打开 app 的时候提示如下错误，点击忽略后发现应用无法正常运行。

![image-20220326224649953](https://img.kuizuo.cn/image-20220326224649953.png)

查看了下我本地的 HBuilderX 版本是正式版 v3.3.13，而该 Vue3 的模板的 Alpha 版 v3.4.3

![image-20220326225748608](https://img.kuizuo.cn/image-20220326225748608.png)

好家伙，官方提供的模板都直接使用 Alpha 版，无奈只好点击 [查看详情](https://ask.dcloud.net.cn/article/35627) 后问题解决办法。最终测试后，建议是使用最新版，即 Alpha 版本，于是替换了本地正式版的 HbuilderX，应用便能正常运行了。

既然开发环境下能正常运行，那就试下打包。由于 uniapp 打包安卓应用只能打包成 APP 资源，要打包成 apk，要么创建一个 Android Studio 工程，然后将 APP 资源放入并打包成 apk，要么使用云打包（而云打包又是只有 HBuilder 才有的功能）。如果本地没有 Android Studio 相关环境，建议还是使用云打包（简单方便），这里就不演示下打包过程了。

### 小程序

这里只测试了微信小程序，在上面 app 的处理完之后，微信小程序也是正常运行，不过至于与上面 Vue3 模板和 HbuilderX 正式版有无关系我就不得而知了，也懒得重装测试了。不过猜测应该与上面无关，毕竟是与手机的 SDK 有关。

## 组件库

uniapp 官方中提供了一个 uni-ui 的组件库，但有一个 uniapp 相对知名的组件库 uview，并且相对前者来说更易上手实用，但当我尝试用 HBuilderX 导入时，却出现下方提示。

![image-20220327002827115](https://img.kuizuo.cn/image-20220327002827115.png)

很显然，uview 并不支持 vue3，但在社区中找到了份同时支持 Vue3.0 和 Vue2.0 的[uView](https://ext.dcloud.net.cn/plugin?name=vk-uview-ui)，但测试后最终已失败告终。

在社区中也搜到了 [ThorUI 组件库](https://ext.dcloud.net.cn/plugin?id=556) 但貌似需要会员收费，果断放弃且没有测试。

然后想到 Taro 中还有 nutui，于是我便开始尝试了一下，不出所料，支持 Vue3 组件库，肯定是支持的。演示如下

![image-20220327005629618](https://img.kuizuo.cn/image-20220327005629618.png)

但很遗憾，这里的支持也只是局限于 h5 开发。官方也有声明只能开发 h5

> @nutui/nutui@next 基于 Vue3 视觉风格 JD APP 10.0 规范 ，只能开发 h5
> @nutui/nutui-taro 基于 Vue3 视觉风格 JD APP 10.0 规范 ，必须基于 taro + vue3 框架 进行开发多端（多端指一套代码 部署多端环境 微信小程序 h5、等第三方小程序）

而且想要多端开发，也必须基于 taro + vue3 框架，所以在 uniapp 上的 app 与小程序上自然无法运行（已测试）

所以说一开始在 uniapp 和 taro 中的选择中，为啥不使用 Taro 呢？而且还支持 Vue3（相比 uniapp 而言）？

最终组件库的选择是 uniapp 官方的 uni-ui。

## 使用 VSCode 开发

HBuilder 给我代码编写体验并不友好，所以将 uniapp 的项目转 vscode 进行开发，并且使用到 npm 包。

首先创建一个 vite+vue3 项目（或者使用一开始介绍的官方提供的 Vue3 模板，主要是有 cli，需要自行在安装），然后将原 src 目录给删除，替换成 uniapp 创建的项目根目录。但还需要做以下操作

### 安装 sass

vite 要支持 sass 只需要安装 sass 的依赖即可

```sh
npm install sass
```

### 允许 js 文件

由于使用了 ts，如果项目中存在 js 文件，将会警告，可以在 tsconfig.json 中添加`"allowJs": true`即可

### 组件语法提示

```sh
npm i @dcloudio/uni-helper-json @types/uni-app @types/html5plus -D
```

但发现对于 uni-ui 组件库的代码提示并不友好，大概率是需要局部引用组件，我这里并未使用[npm 包](https://www.npmjs.com/package/@dcloudio/uni-ui)的方式导入，而是采用官方的 uni_modules，不过组件库的代码提示的问题不是很大，查阅文档即可解决。

### 导入代码块

[uni-app 代码块（vscode） (github.com)](https://github.com/zhetengbiji/uniapp-snippets-vscode)

### 找不到模块“./App.vue”或其相应的类型声明

在 src 目录下创建`env.d.ts`文件，填入以下内容即可

```typescript
/// <reference types="vite/client" />

declare module '*.vue' {
  import { DefineComponent } from 'vue'
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/ban-types
  const component: DefineComponent<{}, {}, any>
  export default component
}
```

然后就是把一些`#ifndef VUE3`不是 vue3 的代码块，以及部分 js 文件改写成 ts 文件即可。这里把我修改后的模板上传到 github 上，有需要的可自行下载：[kuizuo/vite-vue3-uniapp (github.com)](https://github.com/kuizuo/vite-vue3-uniapp)

如果不想使用官方的 vue3 模板，这里也有篇文章介绍如何迁移

[迁移 HbuilderX 的 uniapp 项目到主流的前端 IDE 开发（支持 VS Code 等编辑器/IDE）](https://zhuanlan.zhihu.com/p/268206071)

不过最终如果要在 app 或小程序端运行，还是得打开 HBuilder。

## 总结

整个过程下来，其实还是 uniapp 对 Vue3 支持不够友好，加上生态没能及时更新。并且官方提供的 Vue3 模板也存在一定问题。

但最终还是使用 uniapp 来进行开发，一是对 Vue3 足够了解加上使用过 uniapp，二是 Taro 对 Vue3 是支持了，但是又该如何编译成 App 这是我主要需求的，最主要还是不想踩一遍 Taro 的坑了。
