---
slug: second-blog-is-docusaurus
title: 第二个博客搭建之Docusaurus
date: 2021-08-20
authors: kuizuo
tags: [blog, docusaurus, project]
keywords: [blog, docusaurus, project]
description: 使用 docusaurus 搭建个人博客，并对其主题进行魔改
image: /img/project/blog.png
sticky: 5
---

博客地址: [愧怍的小站](https://kuizuo.cn/)

时隔近半年没好好整理文章，博客也写的不像个人样。:joy:

大半年没更新博客，一直忙着写项目（写到手软的那种），然后无意间在 B 站看到一个 Up 主 [峰华前端工程师](https://zxuqian.cn/) 基于 React 驱动的静态网站生成器搭建的个人博客。第一眼看到该站点的时候惊艳到我了，于是我在其基础上并魔改了一些页面功能，作为个人站点使用。

> 不过国内 docusaurus 的使用者是真的少，Vuepress 都快烂大街了...

<!-- truncate -->

## 安装

如果你想搭建一个类似的博客，可以 [fork 本项目](https://github.com/kuizuo/blog/fork)，修改个人信息，并将文章迁移过来。这里推荐使用 [Vercel 部署个人博客](https://kuizuo.cn/vercel-deploy-blog)，以下是本地安装示例。

```bash
git clone https://github.com/kuizuo/blog
cd blog
yarn
yarn start
```

关于主题魔改可以看 [Docusaurus 主题魔改](https://kuizuo.cn/docs/docusaurus-guides)

## 一些页面

### [博客页](/)

![image-20230221120937768](https://img.kuizuo.cn/image-20230221120937768.png)

- 支持 3 种博文信息展示
- 博客个人信息卡片
- 可根据 `sticky` 字段对文章进行置顶推荐

### [归档页](/archive)

![image-20220804052418993](https://img.kuizuo.cn/image-20220804052418993.png)

### [资源导航](/resource)

![image-20220804052016538](https://img.kuizuo.cn/image-20220804052016538.png)

- 在此分享所收藏的一些好用、实用网站。

### 评论

![image-20220804052746803](https://img.kuizuo.cn/image-20220804052746803.png)

- 接入 [giscus](https://giscus.app) 作为评论系统，支持 GitHub 登录。

### [项目](/project)

![image-20220804052117492](https://img.kuizuo.cn/image-20220804052117492.png)

- 存放你的项目，或是当做一个作品集用于展示。

## 部署

按传统的方式，你编写好一篇文章后，需要重新打包成静态文件（.html），然后将静态文件上传到服务器（需要自己准备）上，然后通过 nginx 配置域名访问。如今有了自动化部署，你只需要将代码 push 到 Github 上，然后通过 CI/CD 自动化部署到服务器上。可以参考 [ci.yml](https://github.com/kuizuo/blog/blob/main/.github/workflows/ci.yml) 配置文件。

这里推荐使用 [Vercel 部署个人博客](/vercel-deploy-blog)，部署十分简单，你甚至不需要服务器，只需要有个 Github 账号，将你的博客项目添加为一个仓库中即可（也许需要科学上网）。

## 最后

博客的意义在于记录，记录自己的成长，记录自己的所思所想，记录自己的所学所得。希望更多的时间用在创作内容上，而不是在搭建博客上。

也就不浪费口舌了，博客搭建完毕，应该好好的去编写有意义的文章，才能够吸引他人的阅读。
