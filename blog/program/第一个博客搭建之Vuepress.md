---
slug: first-blog-is-vuepress
title: 第一个博客搭建之Vuepress
date: 2020-08-30
authors: kuizuo
tags: [blog, vuepress, project]
keywords: [blog, vuepress, project]
---

感谢 [vuepress-theme-reco](https://vuepress-theme-reco.recoluan.com/)主题与一篇博客使用文章[使用 vuepress 构建个人博客](https://lookroot.cn/views/article/vuepress.html#reco%E4%B8%BB%E9%A2%98)

在写这篇文章前，本人非前端专业人士，只是一时兴起想开始搭建一个博客，在该博客上记录与分享一下自己所学的一切内容。（然后现在都在往前端这方向走了:joy:）

<!-- truncate -->

## 补充

不打算破坏之前所写的一些内容，将一些补充的内容写在开头，目前访问 kzcode.cn 依旧能访问到该站，不过文章都保留原有未变动，图片都是直接跟随 MD 文档下，加上服务器又比较拉，所以访问会稍带卡顿。这篇合理来说也算我的第一篇博客，所以还是有必要记录一下的。

## 为什么写博客

在接触软件行业的这一年里，也学到了很多很多很多的知识，也让我感受到代码的魅力与强大。在这学习过程中，百度到了各种相关学习文章，而这些正式前辈们所分享的学习经历，倘若没有这些，我可能早已停下学习的步伐。一时兴起，萌生了搭建博客的想法，然后开始搜索搭建博客的知识，于是乎就有了这篇文章。

写博客是为了记录自己，记录自己学习中的过程，知识，遇到的坑，写成一篇文章，也许过了几个月后的自己脑子不好使，忘记是如何解决的，回过头来看，瞬间焕然大悟。同时也能巩固自己所学的，在如今这个时代，技术更新换代是真的快，而要求学的东西也就越来越多。有时候学过的一项技术，过了几个月真的说忘就忘，不时常记录一下当初写的笔记，翻看之前写过的代码，那真的就和重新学习没什么两样了。

在此期间曾遇到许多坑，而解决最好的办法就是百度。在百度搜索过程中看到了许许多多的学习者分享自己那时候与我遇到一样的问题，说明他是如何解决的，并写文章。有时运气好可能他的解决办法同样也是我的解决办法，但往往总是不尽人意，这时需要再看下一个相关搜索或者下下个才能解决我的问题，这在学习过程中是必不可少的一个环节。而他们所分享的内容，就是一篇篇的博客。正是这一篇篇博客解惑学习者学习中的问题，让他们有自信再去学习下去！

于是就萌生的一种想法，利用自己所学的 Web 知识开始搭建属于自己的个人博客，分享自己所遇到的坑，希望能解决遇到同样问题的人。

### 初步搭建博客界面

要展示给别人看，就必须得搞前端 UI 界面，同时为了快速开发，我又百度了相关的前端 UI 框架，其中决定用 layui，界面风格布局可以接受，于是乎在搜索用过 layui 框架搭建的个人博客，成功找到一篇博主[燕十三一个人的江湖](https://www.yanshisan.cn/)分享的模板源码，然后开始大改，最终花了几个小时修改了大致页面

![image-20200901012343086](https://img.kuizuo.cn/image-20200901012343086.png)

然后问题来了，前端大致界面设计好了，我最关心的文章要怎么写。。。而这份源码是没有给后端这些的（此时的我刚入前端，后端毛也不会），就一个纯前端页面，连文章模板都没有，可能是真的没什么可整理的，于是就放弃了自己手动搭建，主要还是那时候太菜了。

就在想用纯静态页面，还是用动态页面，对于动态页面获取文章数据的技能并不熟练。然后发现这种想法并不行，还是得借助外界提供现有的博客系统来写，于是乎停滞了一段时间，去搜索一系列相关的博客系统（合理来说应该是静态文件生成器），如 Hexo 或 WordPress，不过为啥选择 vuepress，因为我那时候正好在学 Vue，于是乎又开始新的一番折腾。不过也好，如果以后写技术文档，vuepress 也是一个非常推荐的选择。后续的话可能会去接触一下 Hexo 的 butterfly 主题，希望学到点东西，能给自己的博客在增添几份美感。

我所用的主题是[vuepress-theme-reco](https://vuepress-theme-reco.recoluan.com/) 也非常推荐用这个主题来写博客，下面会简单介绍这款主题

## reco 主题

> 一款简洁而优雅的 vuepress 博客 & 文档 主题。官方文档[立即前往](https://vuepress-theme-reco.recoluan.com/)

![image-20200515152702435](https://img.kuizuo.cn/152702-539475.png)

### **安装**

```sh
#全局安装vuepress-reco
npm install @vuepress-reco/theme-cli -g

# 初始化 (blog改成你要的文件名)  然后填写项目标题等等
theme-cli init blog

# 进入项目目录
cd blog

#安装依赖包
npm install

# 运行
npm run dev

# 编译
npm run build
```

执行完`npm run dev`运行后，点击控制台的对应地址 你就能看到

![image-20200901191643031](https://img.kuizuo.cn/image-20200901191643031.png)

当然，可能标题和一些会不一样，因为我更改了两处地方一处是`blog`下的`README.md`文件，文件结构如下

```markdown
---
home: true
heroText: 愧怍的个人空间
tagline: 我是愧怍,沉迷于代码无法自拔
...
```

这个是决定首页的样式，具体要什么背景，内容就因人而异。

另一处是`.vuepress\config.js`里的内容，内容有点多，我依次来讲

首先是开头几行的，title 决定你网站的标题，description 则是一开始出场界面的描述

```js {2-3}
module.exports = {
  title: '愧怍的小站',
  description: '如果代码都解决不了的话,那可能真的解决不了',
}
```

随后你要关注的就是 themeConfig 下的 author，也就是作者名，改成你的名字就行

```js {1,5,6}
    "logo": "/logo.png",
    "search": true,
    "searchMaxSuggestions": 10,
    "lastUpdated": "Last Updated",
    "author": "愧怍",
    "authorAvatar": "/logo.png",
    "record": "xxxx",
    "startYear": "2017"
```

其余的一些，比如`logo.png`与`avatar.png`啊，你换成你的想要的头像就行，他们都存放在.`vuepress\public`下,然后就是修改标题栏，他们都放在`themeConfig`下的`nav`里，这里你想修改哪个导航栏，就改哪个导航栏与标题，文末我会放上我的全部代码。

```js
"themeConfig": {
    "nav": [
      {
        "text": "Home",
        "link": "/",
        "icon": "reco-home"
      },
      {
        "text": "TimeLine",
        "link": "/timeline/",
        "icon": "reco-date"
      },
      {
        "text": "Docs",
        "icon": "reco-message",
        "items": [
          {
            "text": "vuepress-reco",
            "link": "/docs/theme-reco/"
          }
        ]
      },
      {
        "text": "Contact",
        "icon": "reco-message",
        "items": [
          {
            "text": "GitHub",
            "link": "https://github.com/recoluan",
            "icon": "reco-github"
          }
        ]
      }
    ],
```

还有一个是主题自带的导航栏配置，这里你只需要更改 text 与 location 即可，其余不建议更改，你到时候写的文章都在依靠这两个

```js
"blogConfig": {
      "category": {
        "location": 2,
        "text": "Category"
      },
      "tag": {
        "location": 3,
        "text": "Tag"
      }
    },
```

zhuyi 你每次修改修改 config 的内容，就需要重新`npm run dev` vuepress 不支持热更新，也就是文件内容给修改了你需要重新编译运行，这是初学接触会遇到的坑。

### 编写文章

现在有了一个页面风格不错，同时还是响应式页面，就差文章了。这时候你就需要了解 vuepress 的[Markdown 拓展](https://vuepress.vuejs.org/zh/guide/markdown.html#front-matter)，我这里简单叙述一下，你该怎么写文章，下面是你要写文章的模板，你只需要关注几个内容就行了，

```markdown
---
title: 笔记模板
date: 2020-08-21
tags:
  - 笔记
categories:
  - 个人学习笔记
author: 愧怍
keys:
  - 'e9bc0e13a8a16cbb07b175d92a113126'
publish: false
isShowComments: false
---

::: tip
这是 tip
:::

<!--more -->

## 这是你的文章内容

正文内容
```

`---` 所包裹的内容就文章简述像下面这样

![image-20200901034715126](https://img.kuizuo.cn/image-20200901034715126.png)

要更改标题，日期外，你还需要更改的是分类 categories 和标签 tags，举个例子，现在我想写一篇文章，标题是 ES6 语法，那么我可以这么写

```yaml
tags:
  - ES6
  - javascript
  - js
categories:
  - JavaScript
```

分类只写一个，可以写`JavaScript`（分类建议大写），标签写多个，然后你把你写的这篇文章，切记放在`blogs`目录下(以后写的博客都放在这里)，同时建一个文件夹名为`JavaScript`，的然后把文章放在这个目录下，文章名随意，建议和标题一样，如 ES6 语法.md。便于你以后分类，请按这样的方式归类文章。

万一我不小心`- JavaScript` 写成了 `- Java`，而并没有文件夹是`Java`的，没关系，也就是你在分类上看到 Java，文章分类不取决于文件夹名，而取决于`categories` 只是文件夹名和`categories`名一致便于分类罢了。

在标签页上，就能看到 ES6，javascript，与 js 的标签，方便定位相关文章

接着把要写的文章内容全都在写在<!--more -->下即可，这里要注意一下，正文内容的标题，从二级标题开始，一级标题就已经是 title 了，在写也没用。

其余相关的 key 和 publish 等相关参数还请读者查看 reco 主题的官方文档[立即前往](https://vuepress-theme-reco.recoluan.com/)与 vuepress 官网[立即前往](https://vuepress.vuejs.org/zh/)

### 样式修改

可能你会局限于 reco 主题的默认样式，这里就说下如何修改样式。如果你会点前端，这应该来说非常简单。

1. 先参考这篇文章 [个人向优化](https://vuepress-theme-reco.recoluan.com/views/other/reco-optimization.html)，我这里简单说明一下，首先一定要把`node_modules`里的`vuepress-theme-reco`这个主题文件夹整个放在`.vuepress\theme\`下，因为有些时候我们是要修改源码来更改样式的，如果你不这样做的话，而是直接修改`node_modules`里面的文件，你`npm install`就会覆盖你修改后的，所以要这一步操作。
2. 当然你已经觉得 reco 主题都很完美了，不需要更改源码，那么你只需要在 `.vuepress/styles/` 来创建文件`index.styl`来方便地添加额外样式（还有一个默认样式，不推荐修改），然后把你要修改的样式代码写在`index.styl`文件里即可，例如我要修改首页的字体颜色，右键检查找到对应的 css 选择器，然后在`index.styl`添加就行，如

```css
.home-blog .hero h1 {
  color: #fff;
}
```

### 部署到服务器上

关于部署到服务器上，如果只是为了让别人能看到你搭建的博客，而不是要购买域名和服务器这些，直接参考文章[使用 vuepress 构建个人博客](https://lookroot.cn/views/article/vuepress.html#reco%E4%B8%BB%E9%A2%98)即可，如果有服务器和域名我这里简单说下怎么个部署法。

```shell
npm run bulid
```

首先执行上一行代码，然后在目录下会生成`public`文件夹，这个文件夹就是你所有的网站静态文件，这时候你需要你的服务器开启一个 web 服务，我这里用的是腾讯云 CentOS 与宝塔面板（至于这两个怎么搞，外面教程太多了），这里我就用 Nginx。然后如下图添加站点

![image-20200918194540550](https://img.kuizuo.cn/image-20200918194540550.png)

因个人情况填写域名，FTP，数据库等等，然后通过 ftp 工具直接传文件至站点对应的目录下，然后访问服务器对应的 ip 地址或者个人域名解析就行了。

不过这个还要手动部署特别麻烦，有没有什么命令能一键部署的，有，这里我推荐一篇文章[一键部署到服务器](https://reinness.com/views/technology-sharing/vuepress/auto_deploy.html#index-js)，解决了我当初一直用 ftp 的痛点。不过有个更简单的自动部署脚本，scp2，有兴趣可以自行查阅。

## 自己搭建遇到的坑

### 图片路径

首先就是 markdown 图片相对路径的坑，在写文章的话，如果涉及的本地图片引入，那么默认不操作的，也就是需要配置一下，默认在当前同级文件下，在创建一个文件名相同的文件夹来存放图片，我这里就以 Typora 为例，如图

![image-20200901180754412](https://img.kuizuo.cn/image-20200901180754412.png)

其次，Typora 的路径是不带`./`，在 vuepress 会被编译成绝对路径。需要在前面添加上`./`，不过主题内已自带插件`markdown-it`，这个问题无需担心。

但常常我们的 md 文件名是中文的，这时候相对路径带有中文，但是 vuepress 会将中文路径进行 url 编码，

不会将你的这些图片编译到静态文件上，所以需要做一些操作

#### 解决方法

1. 安装 markdown-it-disable-url-encode

```sh
npm i markdown-it-disable-url-encode
```

2. 在.vuepress/config.js 中配置如下

```js
  markdown: {
    extendMarkdown: md => {
      md.use(require("markdown-it-disable-url-encode"));
    }
  },
```

现在你用 Typora 就引用本地图片就可以在 vuepress 中完美显示了。

> 参考 [Vuepress 图片资源中文路径问题](https://segmentfault.com/a/1190000022275001) 完美解决上述问题

### 引入 UI 组件库报错

如果你在该主题使用其他 UI 组件库，如 element，ant design，那么你很有可能会编译失败，官方解释

![image-20201223042921876](https://img.kuizuo.cn/image-20201223042921876.png)

解决办法很简单，先删除 node_modules，然后**再安装 ui 组件库**依赖后，再安装其他依赖就行了。

## 放一些链接

放一些自己搭建这个博客过程中用到的一些链接地址，主要针对插件安装这些

- [VuePress 官网](https://vuepress.vuejs.org/zh/)
- [VuePress 社区](https://vuepress.github.io/)
- [awesome-vuepress](https://github.com/vuepress/awesome-vuepress)
- [reco 主题](https://vuepress-theme-reco.recoluan.com/)
- [一个非常详细的搭建教程](https://blog.csdn.net/sudadaipeng1/article/details/102971008#%e6%b7%bb%e5%8a%a0svg-label%e6%a0%87%e7%ad%be)

## 总结

就此，就可以好好的编写文章，主题固然方便，快捷搭建博客同时也别光顾这美化博客，注重分享文章，这才是博客的真正意义。reco 的主题也是希望帮助更多的人花更多的时间在内容创作上，而不是博客搭建上。

在使用 Vuepress 的一段时间，发现他更适合写的是文档，写博客可以，但花里胡哨的点少，比较简约，对于我这种又爱折腾的人来说，后续有可能会借鉴 Hexo 博客的一款主题 butterfly，将其源码复制到目前这个博客上，顺便巩固下自己的前端设计基础。

但还是要说的，要看自己到底要不要搭建博客，记录与分享文章，别盲目跟从。同时如果搭建博客，请把重心放在创作和笔记上，反复去美化主题对技术的提升远不如一篇有技术性的文章总结。

最后，希望我所分享的所有内容，正是你目前所遇到的难题，能为你排坑，便足矣。
