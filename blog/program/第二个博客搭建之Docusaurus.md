---
slug: second-blog-is-docusaurus
title: 第二个博客搭建之Docusaurus
date: 2021-08-20
authors: kuizuo
tags: [blog, docusaurus, project]
sticky: true
---

博客地址: [愧怍 (kuizuo.cn)](https://kuizuo.cn/)

源码地址：[kuizuo/blog: 愧怍的个人博客 (github.com)](https://github.com/kuizuo/blog)

时隔近半年没好好整理文章，博客也写的不像个人样。:joy:

大半年没更新博客，一直忙着写项目（写到手软的那种），然后无意间在 B 站看到一个 Up 主[峰华前端工程师- 让你学会前端开发 (zxuqian.cn)](https://zxuqian.cn/)推荐的一个基于 React 驱动的静态网站生成器，其实也可以理解为就是 React 版的 Vuepress（主要都是文档类为主）。第一眼看到的时候惊艳到我了，代码也开源了，不妨搭建了一个，立马 git clone 了源码并翻看了下文档，就开始乏而无味的码字。

不过国内 docusaurus 的使用者是真的少。Vuepress 都快烂大街了...

<!-- truncate -->

## 搭建过程

首先还是要再鸣谢一下，基于这位大佬所开源的代码上进行二开（其实也就是换了个背景，删了一下谷歌的广告和 B 站视频的评论，还有一些不必要的百度推送和统计插件），然后就花了点是时间整理下这些年（其实就两年）所涉及的技术栈。

之所以会搭建该博客，主要是 kuizuo.cn 的域名也正好备案完了，但之前的那个博客实在些不下去了（毕竟半年没更新了），然后自己的技术栈也准备转型了，之前前端的技术栈，都是处于 Vue2.0 + JavaScript，vue2 差不多已经玩烂了（尤其是 element ui），书也看的差不多了，加之 Vue3 出了大半年了（前端技术更新迭代是真滴快），正好 B 站尚硅谷的视频出了[【尚硅谷】2021 最新 Vue 迅速上手教程丨 vue3.0 入门到精通\_哔哩哔哩\_bilibili](https://www.bilibili.com/video/BV1Zy4y1K7SH)（强烈推荐！！！），于是就趁暑假时间恶补了一手 Vue3，顺便找了一个开源项目[Vben Admin (vvbin.cn)](https://vvbin.cn/doc-next/)，所采用的都是最新的技术栈 Vue3、Vite、TypeScript（以后写新项目就靠它了），然后该博客又是基于 React ，所以索性把 React 给学了一下，便开始搭建该博客。

### 背景

说一下部分更改的地方，首先就是主页的背景图了，这个是从网站[unDraw - Open source illustrations for any idea](https://undraw.co/)上找的一张 SVG 的图片，如下图

![image-20210815230103523](https://img.kuizuo.cn/image-20210815230103523.png)

怎么说呢，总感觉有些别扭（可能屏幕都是蓝色的搞得好像是 window 蓝屏似的），就暂时先用首页的这张图充当一下。到时候在重新设计一下吧。

补: 已更改为目前首页的背景

### 去谷歌广告

源代码中是有添加谷歌广告的，虽然说如果有一定的访问量，每个月也能有一笔额外收入，不过为了简洁和一些繁琐的广告，就在对应的代码处进行注释。（说不准以后会用的上呢）

### TypeScript 支持

[TypeScript 支持 | Docusaurus](https://docusaurus.io/zh-CN/docs/typescript-support)

```sh
npm install --save-dev typescript @docusaurus/module-type-aliases @tsconfig/docusaurus
```

随后将以下内容添加到您的项目根目录的 `tsconfig.json`：

```json title="tsconfig.json"
{
  "extends": "@tsconfig/docusaurus/tsconfig.json"
}
```

但也只是改善编辑体验，不过就已经足够了。

### 配置 algolia

[搜索 | Docusaurus](https://docusaurus.io/zh-CN/docs/search)

有两种方式来配置algolia，一种是Docsearch 每周一次爬取你的网站，但前提是项目是**开源的**，其好处是申请后会直接给你`appId`、`apiKey`、`indexName`，直接填写至docusaurus.config.js即可。第二种则是自己运行DocSearch 爬虫，可以随时爬取，但需要自行去注册账号与搭建爬虫环境（docker）。

关于申请Algolia DocSearch在文档中有详细介绍，主要是要等，同时注意邮箱信息。如果申请成功后就可以在[Crawler Admin Console](https://crawler.algolia.com/admin/crawlers) 中查看

![image-20220627232545640](https://img.kuizuo.cn/image-20220627232545640.png)

#### 手动爬取

[Run your own | DocSearch (algolia.com)](https://docsearch.algolia.com/docs/run-your-own)

这里我叙述下第二种方式的配置的过程，首先去申请 [Algolia](https://www.algolia.com/) 账号，然后在左侧 indices 创建索引，在 API Keys 中获取 Application ID 和 API Key（注意，有两个 API KEY）

![image-20210821230135749](https://img.kuizuo.cn/image-20210821230135749.png)

![image-20210821230232837](https://img.kuizuo.cn/image-20210821230232837.png)

填入到`docusaurus.config.js`中的 API KEY 是 **Search-Only API Key**

```js
themeConfig: {
    algolia: {
      apiKey: "xxxxxxxxxxx",
      appId: "xxxxxxxxxxx",
      indexName: "kuizuo",
    },
}
```

系统我选用的是 Linux，在 Docker 的环境下运行爬虫代码。不过要先 [安装 jq ](https://github.com/stedolan/jq/wiki/Installation#zero-install) 我这里选择的是 0install 进行安装（安装可能稍慢），具体可以查看文档，然后在控制台查看安装结果

```
[root@kzserver kuizuo.cn]# jq --version
jq-1.6
```

接着在任意目录中创建`.env`文件，填入对应的 APPID 和 API KEY（这里是`Admin API Key`，当时我还一直以为是 Search API Key 坑了我半天😭）

```js
APPLICATION_ID = YOUR_APP_ID
API_KEY = YOUR_API_KEY
```

然后创建`docsearch.json`文件，然后填入对应的配置代码，这里贴下配置[docsearch-configs/docsearch.json](https://github.com/algolia/docsearch-configs/blob/master/configs/docsearch.json)

更改索引名与网站名

```json title="docsearch.json"
{
  "index_name": "kuizuo",
  "start_urls": [
    "https://kuizuo.cn/"
  ],
  "sitemap_urls": [
    "https://kuizuo.cn/sitemap.xml"
  ],
  ...
}
```

运行 docker 命令

```sh
docker run -it --env-file=.env -e "CONFIG=$(cat docsearch.json | jq -r tostring)" algolia/docsearch-scraper
```

接着等待容器运行，爬取你的网站即可。最终打开 algolia 控制台提示如下页面则表示成功

![image-20210821225934002](https://img.kuizuo.cn/image-20210821225934002.png)

不过还是建议使用去申请Docsearch，其每周自动爬取站点，而不是手动爬取。

## 部署

由于我是有个人的域名和服务器，所以之前部署项目都是直接将编译后的文件直接上传至服务器上，然后通过 nginx 就可以直接通过域名访问了，优点的话就是方便，但缺点很明显，每次更新一篇博客的话，就需要重新编译，然后重新拉去文件，并不能做到自动化编译部署。于是就想着采用第三方服务进行部署。

这里推荐使用Vercel，我写过一篇 [Vercel部署个人博客](/develop/Vercel部署个人博客) 的文章，部署十分简单。

## 额外功能页面

#### 资源导航

老早之前就想整理一下自己的网页书签，奈何一直都没怎么有空去处理（其实就是懒），有时候明明看到一个特别好的资源，然而几天后想在重新再找的时候就犹如海底捞针似的。书签收藏夹也是乱的不像样（咋和我电脑桌面和显示桌面一样乱呢，不过好在我有[EveryThing](https://www.voidtools.com/zh-cn/)）

相关链接：[资源导航](https://kuizuo.cn/resources)

#### 评论

相关文章: [Docusaurus 配置 Gitalk 评论插件](https://kuizuo.cn/develop/Docusaurus配置Gitalk评论插件)

#### 实战项目

相关链接：[实战项目](https://kuizuo.cn/project)

确实写过挺多项目，但大多数不方便展示，要么是小工具类 demo，要么是客户定制的，这些总不好直接展示，所以一般展示的都是些非盈利性，功能性的，当然肯定是会附带源码的那种。

## 最后

我个人是比较满意该博客的，搜索，SEO，暗黑模式，博客列表，没有其他博客系统那么花里胡哨的，该有的整洁都有了，最主要是我个人不喜欢文章配背景图，尤其是那种与文章毫不相干的图，图片也许能减少阅读疲倦感，但欣赏的是内容的，而不是背景。

而且又是基于 Docusaurus，到时候是用来做一个项目的文档也方便许多。

还是要感谢下该大佬所开源的代码，同时 B 站视频教程也非常好，让我学到了一些前沿的前端技术。:smile:

也就不多浪费口舌了，博客既然搭建好了，那么接下来就可以专心的编写文章了。
