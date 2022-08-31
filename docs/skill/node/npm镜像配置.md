---
id: npm-mirror-config
slug: /npm-mirror-config
title: npm镜像配置
date: 2022-03-17
authors: kuizuo
tags: [node, npm, electron]
keywords: [node, npm, electron]
---

<!-- truncate -->

由于原淘宝 npm 域名（**http://npm.taobao.org 和 http://registry.npm.taobao.org**）将于 **2022.06.30 号正式下线和停止 DNS 解析**，不妨提前修改镜像的地址，以免受到影响。

域名切换规则：

- http://npm.taobao.org => http://npmmirror.com
- http://registry.npm.taobao.org => http://registry.npmmirror.com

同时不推荐使用镜像下载依赖，因为有可能会导致与官方包不同步（亲测，就因为下载依赖折腾了一晚上，还以为是电脑问题），但有时候开启科学上网（或者没有），下载也不见得特别快，所以这时候才会使用国内镜像。

## 镜像站点

[npmmirror 中国镜像站](https://www.npmmirror.com/)

http://registry.npmjs.org

## 单次使用镜像

```sh
npm install [name] --registry=https://registry.npmmirror.com
```

## 永久配置镜像

```sh
npm config set registry https://registry.npmmirror.com
```

## 查看镜像

```
npm get registry
```

## nrm镜像管理工具

```
npm install nrm -g
```

### nrm ls 查看所有镜像

```
  npm ---------- https://registry.npmjs.org/
  yarn --------- https://registry.yarnpkg.com/
  tencent ------ https://mirrors.cloud.tencent.com/npm/
  cnpm --------- https://r.cnpmjs.org/
  taobao ------- https://registry.npmmirror.com/
  npmMirror ---- https://skimdb.npmjs.com/registry/
```

### nrm use 镜像 切换镜像

```
nrm use taobao
```

## 清除 npm 缓存

```sh
npm cache clean --force
```

## 配置 electron 镜像

```sh
npm config set ELECTRON_MIRROR https://npmmirror.com/mirrors/electron/

npm config set ELECTRON_BUILDER_BINARIES_MIRROR https://npmmirror.com/mirrors/electron-builder-binaries/
```

