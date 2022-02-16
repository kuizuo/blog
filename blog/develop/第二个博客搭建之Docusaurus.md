---
title: 第二个博客搭建之Docusaurus
date: 2021-08-20
authors: kuizuo
tags: [blog, docusaurus]
sticky: true
---

博客地址: [愧怍的小站 (kuizuo.cn)](https://kuizuo.cn/)

源码地址：[kuizuo/blog: 愧怍的个人博客 (github.com)](https://github.com/kuizuo/blog)

时隔近半年没好好整理文章，博客也写的不像个人样。:joy:

大半年没更新博客，一直忙着写项目（写到手软的那种），然后无意间在 B 站看到一个 Up 主[峰华前端工程师- 让你学会前端开发 (zxuqian.cn)](https://zxuqian.cn/)推荐的一个基于 React 驱动的静态网站生成器，其实也可以理解为就是 React 版的 Vuepress（主要都是文档类为主）。第一眼看到的时候惊艳到我了，代码也开源了，不妨搭建了一个，立马 git clone 了源码并翻看了下文档，就开始乏而无味的码字。

不过国内 docusaurus 的使用者是真的少。Vuepress 都快烂大街了...

<!-- truncate -->

## 搭建过程

首先还是要再鸣谢一下，基于这位大佬所开源的代码上进行二开（其实也就是换了个背景，删了一下谷歌的广告和 B 站视频的评论，还有一些不必要的百度推送和统计插件），然后就花了点是时间整理下这些年（其实就两年）所涉及的技术栈。

之所以会搭建该博客，主要是 kuizuo.cn 的域名也正好备案完了，但之前的那个博客实在些不下去了（毕竟半年没更新了），然后自己的技术栈也准备转型了，之前前端的技术栈，都是处于 Vue2.0 + JavaScript，vue2 差不多已经玩烂了（尤其是 element ui），书也看的差不多了，加之 Vue3 出了大半年了（前端技术更新迭代是真滴快），正好 B 站尚硅谷的视频出了[【尚硅谷】2021 最新 Vue 迅速上手教程丨 vue3.0 入门到精通\_哔哩哔哩\_bilibili](https://www.bilibili.com/video/BV1Zy4y1K7SH)（强烈推荐！！！），于是就趁暑假时间恶补了一手 Vue3，顺便找了一个开源项目[Vben Admin (vvbin.cn)](https://vvbin.cn/doc-next/)，所采用的都是最新的技术栈 Vue3、Vite、TypeScript（以后写新项目就靠它了），然后该博客又是基于 React ，所以索性把 React 给学了一下，便开始搭建该博客。


### 背景

说一下部分更改的地方，首先就是主页的背景图了，这个是从网站[unDraw - Open source illustrations for any idea](https://undraw.co/)上找的一张 SVG 的图片，不过显示屏有点多，于是我尝试自己编辑一下，，如下图

![image-20210815230103523](https://img.kuizuo.cn/image-20210815230103523.png)

怎么说呢，总感觉有些别扭（可能屏幕都是蓝色的搞得好像是 window 蓝屏似的），就暂时先用首页的这张图充当一下。到时候在重新设计一下吧。

### 去谷歌广告

源代码中是有添加谷歌广告的，虽然说如果有一定的访问量，每个月也能有一笔额外收入，不过为了简洁和一些繁琐的广告，就在对应的代码处进行注释。（说不准以后会用的上呢）

### 配置 algolia

[搜索 | Docusaurus](https://docusaurus.io/zh-CN/docs/search)

源码中的 algolia 是原作者的博客，这边就需要注册[Algolia](https://www.algolia.com/)的账号，申请相关密钥，然后填入到对应的配置即可。

这里我叙述下配置的全过程（毕竟配置了几个小时）

先去申请 Algolia 账号，然后在左侧 indices 创建索引，在 API Keys 中获取 Application ID 和 API Key（注意，有两个 API KEY）

![image-20210821230135749](https://img.kuizuo.cn/image-20210821230135749.png)

![image-20210821230232837](https://img.kuizuo.cn/image-20210821230232837.png)

填入到`docusaurus.config.js`中的 API KEY 是 Search-Only API Key

```js
themeConfig: {
    algolia: {
      apiKey: "xxxxxxxxxxx",
      appId: "xxxxxxxxxxx",
      indexName: "kuizuo",
    },
}
```

然后到[DocSearch: Search made for documentation | DocSearch (algolia.com)](https://docsearch.algolia.com/apply/)填写自己的网站和邮箱

![image-20210821224447058](https://img.kuizuo.cn/image-20210821224447058.png)

然后每 24 小时便会运行一次代码爬取你的网站生成，但是呢，我这边等了一直没生效，于是乎我决定自己运行爬虫代码，推送到 algolia

#### 手动爬取

这是操作文档 [Run your own | DocSearch (algolia.com)](https://docsearch.algolia.com/docs/run-your-own)

系统我选用的是 Linux，在 Docker 的环境下运行爬虫代码，所以 docker 肯定是要安装的

不过要先安装 jq [安装 jq (github.com)](https://github.com/stedolan/jq/wiki/Installation#zero-install) 我这里选择的是 0install 进行安装（安装可能稍慢），具体可以查看文档，然后在控制台查看安装结果

```
[root@kzserver kuizuo.cn]# jq --version
jq-1.6
```

接着在任意目录中创建`.env`文件，填入对应的 APPID 和 API KEY（这里是`Admin API Key`，当时我还一直以为是 Search API Key 坑了我半天）

```js
APPLICATION_ID = YOUR_APP_ID;
API_KEY = YOUR_API_KEY;
```

然后创建一个`docsearch.json`文件（名字随便），然后填入对应的配置代码，这里贴下对应链接[docsearch-configs/docsearch.json at master · algolia/docsearch-configs (github.com)](https://github.com/algolia/docsearch-configs/blob/master/configs/docsearch.json)

更改索引名与网站名

```json
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

接着等待容器运行，爬取你的网站即可

```
[root@kzserver kuizuo.cn]# docker run -it --env-file=.env -e "CONFIG=$(cat docsearch.json | jq -r tostring)" algolia/docsearch-scraper
Getting https://kuizuo.cn/sitemap.xml from selenium
Getting https://kuizuo.cn/ from selenium
> DocSearch: https://kuizuo.cn/ 12 records)
Getting https://kuizuo.cn/essay from selenium
Getting https://kuizuo.cn/resources from selenium
Getting https://kuizuo.cn/docs/skill from selenium
Getting https://kuizuo.cn/page/2 from selenium
Getting https://kuizuo.cn/tags/terminal from selenium
Getting https://kuizuo.cn/Windows%20Terminal%E7%BE%8E%E5%8C%96 from selenium
Getting https://kuizuo.cn/Js%E6%95%B0%E7%BB%84%E5%AF%B9%E8%B1%A1%E5%8E%BB%E9%87%8D from selenium
Getting https://kuizuo.cn/tags/chrome from selenium
Getting https://kuizuo.cn/Wappalyzer%E8%AF%86%E5%88%AB%E7%BD%91%E7%AB%99%E4%B8%8A%E7%9A%84%E6%8A%80%E6%9C%AF from selenium
Getting https://kuizuo.cn/tags/%E5%B7%A5%E5%85%B7 from selenium
Getting https://kuizuo.cn/tags/vscode from selenium
```

最终打开 algolia 控制台提示如下页面则表示成功

![image-20210821225934002](https://img.kuizuo.cn/image-20210821225934002.png)

整体下来还算 OK，主要是接触和.env 文件配置和 Docker 的使用，配置完后使用全文搜索感觉就不一样，能精确定位到每一个字的同时，还能显示最近浏览的记录，也算是让我接触到了一个新的技能点。

## 部署

由于我是有个人的域名和服务器，所以之前部署项目都是直接将编译后的文件直接上传至服务器上，然后通过 nginx 就可以直接通过域名访问了，优点的话就是方便，但缺点很明显，每次更新一篇博客的话，就需要重新编译，然后重新拉去文件，并不能做到自动化编译部署。于是就想着采用第三方服务进行部署。

### webify

[5 分钟，从 0 到 1 上线个人网站！ (juejin.cn)](https://juejin.cn/post/6990200172840124424)

webify 是腾讯云的 Web 应用托管服务，可以将本地代码

![image-20210818205645939](https://img.kuizuo.cn/image-20210818205645939.png)

这里我选择 Docusaurus2，毕竟我用的就是这个

接着选择托管平台（Github，Gitlab，Gitee），这里我就选择 Github，然后新建仓库，然后给项目命名，部署应用，静等即可。

![image-20210818205903137](https://img.kuizuo.cn/image-20210818205903137.png)

然后访问所提供域名（虽然很长，但是能访问）

![image-20210818210104842](https://img.kuizuo.cn/image-20210818210104842.png)

然后只需要将本地的代码覆盖到远程仓库，或者一开始创建的时候就从 Github 拉去代码。此后，只要一将代码上传至远程仓库（原理是在仓库中添加了一个 Webhooks），webify 就会自动拉去对应的代码，并进行 npm build，就此一个能自动化部署的博客就搭建完毕了。

#### 添加自定义域名

那么长的域名肯定不是我想要的，于是就点击应用设置，在自定义域名配置中添加域名即可

![image-20210818210410275](https://img.kuizuo.cn/image-20210818210410275.png)

:::danger

要注意的是，如果域名已经上 CDN 了，那么就需要解除才行，不然就会提示 cdn resource exist

:::


好用的好用，但是要花钱滴。是按量计费的。

![image-20210818220427224](https://img.kuizuo.cn/image-20210818220427224.png)

不过费用确实不高，容量 5g 也就 2.1 元（都不够买包零食），如果网站不是大规模的流量入侵，基本也够用了（万一没人访问，甚至都不用花钱买资费包），我目前也就是使用 webify 部署该博客，主要是在国内，同时也提供对应的 CDN 服务能及极大提高访问速度，确实快了不少。

还有其他的第三方托管平台，就比如 gitHub 中的 GitHub Actions。

### 额外功能页面

#### 资源导航

老早之前就想整理一下自己的网页书签，奈何一直都没怎么有空去处理（其实就是懒），有时候明明看到一个特别好的资源，然而几天后想在重新再找的时候就犹如海底捞针似的。书签收藏夹也是乱的不像样（咋和我电脑桌面和显示桌面一样乱呢，不过好在我有[EveryThing](https://www.voidtools.com/zh-cn/)）

相关链接：[资源导航](https://kuizuo.cn/resources)

#### 评论

相关文章: [Docusaurus配置Gitalk评论插件](https://kuizuo.cn/develop/Docusaurus配置Gitalk评论插件)

#### 实战项目

相关链接：[实战项目](https://kuizuo.cn/project)

确实写过挺多项目，但大多数不方便展示，要么是小工具类demo，要么是客户定制的，这些总不好直接展示，所以一般展示的都是些非盈利性，功能性的，当然肯定是会附带源码的那种。

## 最后

我个人是比较满意该博客的，搜索，SEO，暗黑模式，博客列表，没有其他博客系统那么花里胡哨的，该有的整洁都有了，最主要是我个人不喜欢文章配背景图，尤其是那种与文章毫不相干的图，图片也许能减少阅读疲倦感，但欣赏的是内容的，而不是背景。

而且又是基于 Docusaurus，到时候是用来做一个项目的文档也方便许多。

还是要感谢下该大佬所开源的代码，同时 B 站视频教程也非常好，让我学到了一些前沿的前端技术。:smile:

也就不多浪费口舌了，博客既然搭建好了，那么接下来就可以专心的编写文章了。
