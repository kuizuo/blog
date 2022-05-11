---
title: Vercel部署个人博客
date: 2022-05-11
authors: kuizuo
tags: [blog, vercel]
---

![image-20220511170700075](https://img.kuizuo.cn/image-20220511170700075.png)

:::tip 观前提醒

vercel 部署静态资源网站极其**方便简单**，并且有可观的**访问速度**，最主要的是**免费部署**。

如果你还没有尝试的话，强烈建议去使用一下。

:::

<!-- truncate -->

## [vercel 介绍](https://zhuanlan.zhihu.com/p/452654619)

## 注册账号

进入[Vercel](https://vercel.com)官网，先去注册一个账号，建议注册一个[Github](https://github.com/)账号后，使用GIthub账号来登录Vercel。

## 部署网站

进入 [Dashboard](https://vercel.com/dashboard)

![image-20220511170233559](https://img.kuizuo.cn/image-20220511170233559.png)

点击 [New Project](https://vercel.com/new)

![image-20220511165902993](https://img.kuizuo.cn/image-20220511165902993.png)

这里可以从已有的 git repository 中导入，也可以选择一个模板。

这里登录我的 Github 账号选择仓库，然后点击 blog 仓库旁的 Import 即可。当然，你也可以直接拉取我的仓库，仓库地址：https://github.com/kuizuo/blog

![image-20220511165513526](https://img.kuizuo.cn/image-20220511165513526.png)

点击 Deploy，然后静等网站安装依赖以及部署，稍后将会出现下方页面。

![image-20220511170700075](https://img.kuizuo.cn/image-20220511170700075.png)

此时项目已经成功搭建完毕了，点击图片即可跳转到 vercel 所提供的二级域名访问。

是不是极其简单？甚至不需要你输入任何命令，便可访问构建好的项目。

## 自定义域名

如果有自己的域名，还可以在 vercel 中进行设置。

首先进入 blog 的控制台，在Settings -> Domains 添加域名。

![image-20220511171144240](https://img.kuizuo.cn/image-20220511171144240.png)

接着提示域名需要 DNS 解析到 vercel 提供的记录值

![image-20220511171359148](https://img.kuizuo.cn/image-20220511171359148.png)

登录所在的域名服务商，根据 Vercel 提供的记录值，添加两条记录

![image-20220511172741663](https://img.kuizuo.cn/image-20220511172741663.png)

此时回到Vercel，可以看到记录值成功生效。

![image-20220511172027570](https://img.kuizuo.cn/image-20220511172027570.png)

此时访问自己的域名，同样也能访问到页面，同时还有可观的访问速度。

### 自动颁发 SSL 证书

默认状态下，Vercel 将会颁发并自动更新 SSL 证书。

![image-20220511172240999](https://img.kuizuo.cn/image-20220511172240999.png)

## 自动构建

> To update your Production Deployment, push to the "main" branch.

当主分支有代码被推送，Vercel 将会重新拉取代码，并重新构建部署（构建速度可观）

![image-20220511173442694](https://img.kuizuo.cn/image-20220511173442694.png)

## Serverless

同时vercel还支持serverless，也就是说，不只是部署一个静态页面，不过肯定有一定的限制。如有机会应该还是会出篇相关文章。
