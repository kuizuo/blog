---
id: install-lsposed
slug: /install-lsposed
title: 安装LSPosed
date: 2021-12-09
authors: kuizuo
tags: [android, 刷机]
keywords: [android, 刷机]
---

<!-- truncate -->

## 高版本安装 Xposed

熟悉安卓逆向都清楚，Xposed 不支持高安卓版本，自从 android 7.0 之后 xposed 的开发者 rovo89 基本就不维护了，针对 android 8.0 的版本草草发布了一个测试版本撒手不管了。如今安卓手机遍地安卓 9 安卓 10 的（本篇写的时候甚至安卓 12 都已发布大半年了），于是便有了一个替代品----Edxposed 框架，Edxposed 全称 Elder driver Xposed Framework，简称 edxp，我的前一部手机 Pixel 便是安装 Edxposed 的，但有个更好的替代品 Lsposed

## 什么是 Lsposed

LSPosed 是一款开源在 GitHub 上的 Xposed 框架，全称：LSPosed Xposed Framework。LSPosed 框架基于 Rirud 的 ART 挂钩框架（最初为 Android Pie）提供与原版 Xposed 相同的 API，利用 YAHFA 挂钩框架，支持 Android 12，在 Android 高权限模式下运行的框架服务，可以在不修改 APK 文件的情况下修改程序的运行，基于它可以制作出许多功能强大的 Xposed 模块，且在功能不冲突的情况下同时运作。

## 为什么是 Lsposed

1️⃣ Edxposed 面临着停更的风险，且稳定性欠佳， Lsposed 则可以保证长期更新，并会持续加入新的功能。
2️⃣ Lsposed 修复了 Edxoosed 的一系列 bug（比如偶尔软重启），并提升了其稳定性和性能。由于 Lsposed 默认开启白名单模式，模块只受用于需要的应用，系统资源的消耗被大大减少，耗电量也有所改善。
3️⃣ 而且，对于绝大多数模块而言，Lsposed 只需重启该应用即可激活，而无需重启整个系统（部分涉及系统框架的模块除外）
4️⃣ 此外，Lsposed 的默认白名单设定使得用户的个人隐私得到保障，进一步加强了系统安全性。借助 Magisk Hide 功能，Lsposed 可以很好地隐藏自己，避免被部分重要应用识别

## 安装

github 地址：[LSPosed/LSPosed: LSPosed Framework (github.com)](https://github.com/LSPosed/LSPosed)

手机配置:

版本: 安卓 12

手机型号: Pixel 4XL

安装 Lsposed 前提是安装 Magisk 模块，这边安装的是最新版即 Magisk v23，关于 Magisk 的安装在上一篇已经呈现了。

### 安装 Riru

又由于我的安卓版本是 12，所以需要下载 Riru v25+

Riru 模块地址：[Releases · RikkaApps/Riru (github.com)](https://github.com/RikkaApps/Riru/releases)

或者直接在 Magisk 模块仓库中搜索 Riru，并安装

### 安装 Lsposed

同样的，安装 Riru 后在 Magisk 模块仓库中搜索 LSPosed（一般在在线首页中就有），然后点击安装后重启便可。![image-20211209162111421](https://img.kuizuo.cn/image-20211209162111421.png)

这时候桌面便会有 LSPosed 应用，这时候就可以愉快去下载 Xposed 模块了。

![image-20211210015027929](https://img.kuizuo.cn/image-20211210015027929.png)
