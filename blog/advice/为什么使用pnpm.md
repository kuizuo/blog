---
slug: why-use-pnpm
title: 为什么使用pnpm
date: 2022-01-08
authors: kuizuo
tags: [node, pnpm]
keywords: [node, pnpm]
---

<!-- truncate -->

[pnpm 文档](https://pnpm.io/zh/)

## 前言

在一个 node 项目中免不了 node_modules 依赖，假设项目 A 用的了 Express 依赖，同时项目 B 也用到了 Express，并且两者所存放的位置不同，那么磁盘空间将会多出两份 Express 依赖，假设有 100 个项目，那么将会有有 100 倍的空间被浪费。这些空间还可以用磁盘空间来弥补，但是这 100 个项目如果都使用 npm i 去下载同样版本依赖，则是实实在在耗费网络资源去下载。

pnpm 能解决以下两点问题

- 包安装速度极快；
- 磁盘空间利用非常高效。

而这些问题是一个 node 项目中常有的。相信此时的你都有点蠢蠢欲动了，而安装也很简单

## 安装

请查阅你的 node 版本与 pnpm 是否匹配 [安装 | pnpm](https://pnpm.io/zh/installation#兼容性)

```
npm install -g pnpm
```

### 升级

```
pnpm add -g pnpm
```

此时 pnpm 就已经安装完了，与 yarn 安装一样，都感觉没安装似的。

## 使用

pnpm 命令几乎与 npm 一样，设置配置的方式也与 npm 相同，这里不妨尝试通过 pnpm 去下载 express 依赖，打开 CMD，将路径改成你平时写 js 代码的地方，切记不要在 C 盘路径下，不然将会在`C:\Users\{userDir}\.pnpm-store\v3`去管理你的所有依赖，至于为什么后文会说，这里选择 F 盘进行安装，安装结果如下。

![image-20220108040813223](https://img.kuizuo.cn/20220108040813.png)

不难看出，它将依赖存放至**`F:\.pnpm-store\v3`**下，但此时查看项目目录的 node_modules 文件夹

![image-20220108041030618](https://img.kuizuo.cn/20220108041030.png)

发现`express`与`mime-types`的右侧带了回车符，而这两个文件夹实际上是 window 的硬链接，而读取的就是存放在`F:\.pnpm-store\v3`下的依赖。虽然查看 node_modules 属性会发现显示的空间貌似和原始的链接所占用的空间一样，但其实是同一个位置，官方中常用问题中也有介绍到 [常见问题 | pnpm](https://pnpm.io/zh/faq#如果包存储在全局存储中为什么我的-node_modules-使用了磁盘空间)，所以真不用担心磁盘空间的问题。

这时候去查看 `F:\.pnpm-store\v3\files` 会发现都是一堆数字与字母命名的文件夹，而依赖都存放至这些杂乱无章的文件名之中。同时.pnpm-store 是根据你所在驱动器（这里是 F 盘）下创建的，可以通过 `pnpm store path`查看，也就是上文为什么说不要在 C 盘路径（包括桌面）去安装依赖了，所以不用担心 C 盘空间会越来越小（如果你的代码是在 C 盘编写的话，那当我没说）。

## 最后

不过还是要提醒一句，即便 pnpm 能解决磁盘问题，但还是存在一定的兼容性，如果一个项目是用 npm 或者 yarn 进行构建的，使用 pnpm 是绝对免不了一些问题，小问题暂时想不到，大问题无法运行，所以请三思再考虑对已有项目是否尝试升级 pnpm。

但我认为还是有必要尝试尝试下，不尝试，怎么能发现新大陆呢。

> 参考链接：[关于现代包管理器的深度思考——为什么现在我更推荐 pnpm 而不是 npm/yarn? - 掘金 (juejin.cn)](https://juejin.cn/post/6932046455733485575#heading-14)
