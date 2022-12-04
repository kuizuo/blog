---
slug: second-blog-is-docusaurus
title: 第二个博客搭建之Docusaurus
date: 2021-08-20
authors: kuizuo
tags: [blog, docusaurus, project]
keywords: [blog, docusaurus, project]
---

博客地址: [愧怍的小站](https://kuizuo.cn/)

源码地址：[kuizuo/blog](https://github.com/kuizuo/blog)

时隔近半年没好好整理文章，博客也写的不像个人样。:joy:

大半年没更新博客，一直忙着写项目（写到手软的那种），然后无意间在 B 站看到一个 Up 主 [峰华前端工程师 ](https://zxuqian.cn/) 基于 React 驱动的静态网站生成器搭建的个人博客。第一眼看到该站点的时候惊艳到我了，于是也想着搭建一个，作为个人站点使用。

不过国内 docusaurus 的使用者是真的少。Vuepress 都快烂大街了...

关于主题魔改可以看 [Docusaurus 主题魔改](/docs/docusaurus-guides)

<!-- truncate -->

## 安装

下载代码，根据相应命令运行即可，在本地运行还是相对比较容易的。

修改了下个人信息，然后将之前的博客文章迁移过来即可。

## 额外功能页面

### [归档页](/archive)

![image-20220804052418993](https://img.kuizuo.cn/image-20220804052418993.png)

### [网址导航](/website)

![image-20220804052016538](https://img.kuizuo.cn/image-20220804052016538.png)

### 评论

![image-20220804052746803](https://img.kuizuo.cn/image-20220804052746803.png)

相关文章: [Docusaurus 配置 Gitalk 评论插件](/docusaurus-gitalk-plugin)

### [项目](/project)

![image-20220804052117492](https://img.kuizuo.cn/image-20220804052117492.png)

## 部署

由于我是有个人的域名和服务器，所以之前部署项目都是直接将编译后的文件直接上传至服务器上，然后通过 nginx 就可以直接通过域名访问了，优点的话就是方便，但缺点很明显，每次更新一篇博客的话，就需要重新编译，然后重新拉去文件，并不能做到自动化编译部署。于是就想着采用第三方服务进行部署。

这里推荐使用 Vercel，我写过一篇 [Vercel 部署个人博客](/vercel-deploy-blog) 的文章，部署十分简单。

## 最后

我个人是比较满意该博客的，搜索，SEO，暗黑模式，博客列表，没有其他博客系统那么花里胡哨的，该有的整洁都有了，最主要是我个人不喜欢文章配背景图，尤其是那种与文章毫不相干的图，图片也许能减少阅读疲倦感，但欣赏的是内容的，而不是背景。

而且又是基于 Docusaurus，到时候是用来做一个项目的文档也方便许多。

还是要感谢下所开源的代码，同时 B 站视频教程也非常好，让我学到了一些前沿的前端技术。:smile:

也就不多浪费口舌了，博客既然搭建好了，那么接下来就可以专心的编写文章了。
