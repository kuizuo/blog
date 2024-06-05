---
slug: pnpm-monorepo-practice
title: pnpm monorepo实践
date: 2022-08-29
authors: kuizuo
tags: [pnpm, monorepo]
keywords: [pnpm, monorepo]
description: 使用 pnpm monorepo 实践
---

老早老早之前就听过 monorepo（单一代码库） 这个名词，也大致了解其出现的意义与功能。但奈何自己的一些小项目中暂时还用不上多项目存储库，所以迟迟没有尝试使用。

但随着越来越多的开源项目使用 monorepo，现在不实践到时候也肯定是要实践的，这次实践也算是为以后的技能先做个铺垫了。

<!-- truncate -->

## 介绍

前言铺垫这么多，就举个例子介绍下 monorepo 的应用场景，比如现在有个 UI 组件库的开源项目。

既然是组件库，首先肯定要有组件库的代码吧，此外可能还有脚手架（CLI）或是工具库（utils）或者是插件要作为 npm 包发布，等等。

如果是传统的开发，每个项目都作为单独的 npm 项目来发布引用，就需要创建多个代码仓库，即**多代码库（multirepos）**。很显然这样在开发以及代码仓库的协同上肯定有弊端，而 monorepo 正是解决这种问题，**将所有的项目在一个代码仓库中，即单一代码库（monorepos）**。

这只是 monorepo 的一个应用场景例子，这里有一个更好的例子 [前端工程化：如何使用 monorepo 进行多项目的高效管理](https://juejin.cn/post/7043990636751503390)，更多可以参考使用 monorepo 的开源项目来了解。在 [这里](https://pnpm.io/zh/workspaces#%E4%BD%BF%E7%94%A8%E7%A4%BA%E4%BE%8B) 可查看使用了 pnpm 工作空间功能的最受欢迎的开源项目。

有篇文章推荐阅读 [5 分钟搞懂 Monorepo - 简书 (jianshu.com)](https://www.jianshu.com/p/c10d0b8c5581)

这里还有份手册可供阅读 [What is a Monorepo? | Turborepo](https://turborepo.org/docs/handbook/what-is-a-monorepo)

## 上手实践

你可以 clone [https://github.com/kuizuo/monorepo-demo](https://github.com/kuizuo/monorepo-demo) 来查看本文示例代码仓库

这里使用 pnpm 的 [workspace](https://pnpm.io/zh/workspaces) 来创建 monorepo 代码仓库，此外目前主流的还有 yarn workspace + [lerna](https://lerna.js.org/)，[nx](https://nx.dev/)，[turborepo](https://turborepo.org/)等等。

### 项目结构

pnpm 内置了对单一存储库（也称为多包存储库、多项目存储库或单体存储库）的支持， 你可以创建一个 workspace 以将多个项目合并到一个仓库中。

pnpm 要使用 monorepo 的话，需要创建 pnpm-workspace.yaml 文件，其内容如下

```YAML
packages:
  - 'packages/*'
```

其中 packages 为多项目的存放路径（一般为公共代码），pnpm 将 packages 下的子目录都视为一个项目。此外如果项目还有文档或在线演示的项目（这些不作为核心库），放在 packages 有些许不妥，就可以像下面这样来配置 workspace

```YAML
packages:
  - packages/*
  - docs
  - play
```

像一开始所举例的代码仓库的项目结构如下

```bash
monorepo-demo
├── package.json
├── packages
│   ├── components          # 组件库
│   │   ├── index.js
│   │   └── package.json
│   ├── cli                 # CLI
│   │   ├── index.js
│   │   └── package.json
│   ├── plugins             # 插件
│   │   ├── index.js
│   │   └── package.json
│   ├── utils               # 工具
│   │   ├── index.js
│   │   └── package.json
├── docs                    # 文档
│   │   ├── index.js
│   │   └── package.json
├── play                    # 在线演示
│   │   ├── index.js
│   │   └── package.json
├── pnpm-lock.yaml
└── pnpm-workspace.yaml
```

其中 packages 下存放的就是多个项目代码库，假设项目就叫 demo（因为到时候这些包是有可能要发布的，而名字就要保证唯一），那么项目的 package.json 如下演示：

```json
{
  "name": "@demo/components",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "type": "module",
  "license": "ISC",
  "dependencies": {
    "@packages/utils": "workspace:^1.0.0"
  }
}
```

### 安装依赖

执行`pnpm install` 会自动安装所有依赖（包括 packages 下），所以我们肯定不会傻傻 cd 到每个目录下，然后执行`pnpm install` 来一个个安装依赖。

假设现在我要为某个项目添加依赖，例如为 utils 模块添加 lodash 的话，按之前可能会 cd 到 utils 目录执行`pnpm add loadsh` ，其实完全不用，pnpm 提供 `--filter` 选项来指定包安装依赖，命令如下

```bash
pnpm --filter <package_selector> <command>
```

例如：

```bash
pnpm -F @demo/utils add lodash
```

> `-F`等价于`--filter`

假设现在写好了 utils 模块，`@demo/components`准备使用 utils 模块，可以按照如下操作

```bash
pnpm -F @demo/components add @demo/utils@*
```

这个命令表示在`@demo/components`安装`@demo/utils`，其中的`@*`表示默认同步最新版本，省去每次都要同步最新版本的问题。

### 启动项目

使用**node packages/component** （默认执行 index.js 文件）

```bash
node packages/components

```

更好的选择是编写 npm scripts 就像下面这样：

```json
  "scripts": {
    "test": "vitest",
    "dev": "pnpm -C play dev",
    "docs:dev": "pnpm run -C docs dev",
    "docs:build": "pnpm run -C docs build",
    "docs:serve": "pnpm run -C docs serve",
  },
```

其中[ -C \<path\>](https://pnpm.io/pnpm-cli#-c-path---dir-path) 表示 在 path 下运行 npm 脚本 而不是在当前工作路径下。例如根目录下执行 `npm run docs:dev` 便会执行 `docs/package.json` `dev`脚本，同理`build`和`serve`也是一样。

此外更多的可能会在根目录下创建 script 脚本，然后编写（编译，发布）脚本。

## Turborepo

在上面只是介绍了使用 pnpm workspace 来搭建一个 monorepo 的仓库，但很多时候还需要搭配适当的工具来扩展 monorepo， Turborepo 就是其中之一，利用先进的构建技术和思想来加速开发，构建了无需配置复杂的工作。

这里就不做介绍，这篇 [🚀Turborepo：发布当月就激增 3.8k Star，这款超神的新兴 Monorepo 方案，你不打算尝试下吗？ - 掘金 (juejin.cn)](https://juejin.cn/post/7129267782515949575) 就非常值得推荐阅读。

## 总结

搭建一个 monorepo 的仓库其实挺简单的，但也并不是什么项目使用 monorepo 就好，想想看，所有项目和依赖都堆积在一起，那么项目启动速度必然不如单项目启动来的快。就比如一个博客项目，就完全不至于将博客细分为文章/评论/搜索等等划分，还不如统一将代码都直接写到 src 目录下。

可以说当使用 monorepo 作为项目管理时，每个模块就相当于按照一个 npm 包发布的方式创建，而不是像 src/utils 那么随便了，而开源项目大部分都是要作为 npm 包的方式发布的，使用 monorepo 来管理多个项目自然也就再合适不过了。

## 相关文章

[5 分钟搞懂 Monorepo - 简书 (jianshu.com)](https://www.jianshu.com/p/c10d0b8c5581)

[前端工程化：如何使用 monorepo 进行多项目的高效管理](https://juejin.cn/post/7043990636751503390)

[pnpm workspace](https://pnpm.io/zh/workspaces)

[🚀Turborepo：发布当月就激增 3.8k Star，这款超神的新兴 Monorepo 方案，你不打算尝试下吗？ - 掘金 (juejin.cn)](https://juejin.cn/post/7129267782515949575)
