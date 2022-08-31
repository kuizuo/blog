---
slug: docusaurus-gitalk-plugin
title: Docusaurus配置Gitalk评论插件
date: 2022-01-22
authors: kuizuo
tags: [blog, docusaurus, gitalk]
keywords: [blog, docusaurus, gitalk]
---

之前使用 vuepress 的时候，使用的评论系统是[Valine](https://valine.js.org/)，可是匿名用户也能直接评论，虽说会过滤垃圾信息，但是后台查看评论与通知总感觉没有那么实在。

然后换到了 docusaurus，并没有内置评论相关的，原本是打算自己写一个评论系统，MongoDB 存储评论数据相对方便些。然后这一拖就是拖到了过年前。。。无意间发现有一个插件[Gitalk](https://gitalk.github.io/)，基于 Github Issue 的，而我平常又经常刷 github，加上需要 github 账号才能评论，所以就使用[Gitalk](https://gitalk.github.io/) 来作为博客的评论（注：Gitalk 是基于 react 编写的）。

<!-- truncate -->

## 操作步骤

### 1、创建评论仓库

首先需要 github 账号，创建一个仓库用于存放评论，由于我的博客是同步上传到[github](https://github.com/kuizuo/blog)上，所以就无需新建仓库

### 2、开启 issues 功能

默认开启，可在 Settings -> Features -> Issues 中设置

![image-20220122141447919](https://img.kuizuo.cn/20220122141447.png)

### 3、注册一个 Github applications

点击[此处](https://github.com/settings/developers)创建或在 github 右上角路径 settings -> Developer settings -> OAuth Apps

![image-20220121225059192](https://img.kuizuo.cn/20220121225106.png)

- Homepage URL：就是博客的网址（如果是 github.io 的 page）
- Authorization callback URL: 就是 github 权限验证的回调地址，一般默认就是域名

### 4、获取 Client ID 和 Client Secret

创建成功后，就可以获取到 Client ID 和 Client Secret 了，保存下来。

![image-20220122130221871](https://img.kuizuo.cn/20220122130222.png)

### 5、安装

[官方教程](https://github.com/gitalk/gitalk/blob/master/readme-cn.md#安装)

- 直接引入

```html
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/gitalk@1/dist/gitalk.css" />
<script src="https://cdn.jsdelivr.net/npm/gitalk@1/dist/gitalk.min.js"></script>

<!-- or -->

<link rel="stylesheet" href="https://unpkg.com/gitalk/dist/gitalk.css" />
<script src="https://unpkg.com/gitalk/dist/gitalk.min.js"></script>
```

- npm 安装

```sh
npm i --save gitalk
```

```javascript
import 'gitalk/dist/gitalk.css'
import Gitalk from 'gitalk'
```

### 6、使用

```html
<div id="gitalk-container"></div>
```

用下面的 Javascript 代码来生成 gitalk 插件：

```javascript
const gitalk = new Gitalk({
  clientID: 'GitHub Application Client ID',
  clientSecret: 'GitHub Application Client Secret',
  repo: 'GitHub repo',
  owner: 'GitHub repo owner',
  admin: ['GitHub repo owner and collaborators, only these guys can initialize github issues'],
  id: location.pathname, // Ensure uniqueness and length less than 50
  distractionFreeMode: false, // Facebook-like distraction free mode
})

gitalk.render('gitalk-container')
```

##### react 中使用

导入 Gitalk 组件与样式

```jsx
import 'gitalk/dist/gitalk.css'
import GitalkComponent from 'gitalk/dist/gitalk-component'
```

使用组件与配置参数

```jsx
<GitalkComponent
  options={{
    clientID: '...',
    // ...
    // options below
  }}
/>
```

我的配置

```javascript
const options = {
  clientID: 'GitHub Application Client ID',
  clientSecret: 'GitHub Application Client Secret',
  repo: 'blog',
  owner: 'kuizuo',
  admin: ['kuizuo'],
  id: title,
  title: title,
  labels: labels,
  distractionFreeMode: false,
}
```

具体参数[gitalk](https://github.com/gitalk/gitalk/blob/master/readme-cn.md#设置)

## 问题

### Error: Not Found

options 有个选项 repo，填写的是仓库名称，不是链接，像上面我所填写的就是`blog`，而不是填写https://github.com/kuizuo/blog

### 未找到相关的 [Issues](https://github.com/kuizuo/blog/issues) 进行评论，请联系 @xxxxx 初始化创建

这里的 xxxxx 就是选项 admin 的内容，首次载入文章的话需要用管理员账号登录初始化一下（也就是新建一个 issues），否则其他人访问也将会提示该信息。

目前暂时没找到有效办法一键加载所有博客的 issues，只要用登录 github 的管理员账号去访问每一篇博客。

其中在[第 3 步](#3注册一个-github-applications)的 Authorization callback URL 地址一定要填写成现在博客线上环境 https://kuizuo.cn ，否则也无法正常使用

### Validation failed

原因是 id 参数不能超过 50 个字符，但是默认是 location.href，有可能会导致长度超过。所以我的做法是 id: title，同时访问页面的时候，会自动为仓库创建一个 issue，标题为文章的标题。

也有可能是请求过于频繁，触发了 Github 的限流机制，需要等待几分钟后恢复。

### react 编译遇到的问题

插件中会使用到浏览器的 window 对象，开发时正常，但是编译就会报错（提示 window is not defined），这边引用了 docusaurus 的[BrowserOnly](https://docusaurus.io/zh-CN/docs/docusaurus-core#browseronly)，将代码封装成如下便可正常编译

```jsx
<BrowserOnly fallback={<div></div>}>{() => <GitalkComponent options={options} />}</BrowserOnly>
```

[查看完整源码点我](https://github.com/kuizuo/blog/blob/main/src/theme/BlogPostPage/index.jsx)

## Github Api

[GitHub Documentation](https://docs.github.com/cn)

通过 github api 还可以获取 issues 列表

访问 https://api.github.com/repos/kuizuo/blog/issues，返回结果如下

```json
[
  {
    "url": "https://api.github.com/repos/kuizuo/blog/issues/24",
    "repository_url": "https://api.github.com/repos/kuizuo/blog",
    "labels_url": "https://api.github.com/repos/kuizuo/blog/issues/24/labels{/name}",
    "comments_url": "https://api.github.com/repos/kuizuo/blog/issues/24/comments",
    "events_url": "https://api.github.com/repos/kuizuo/blog/issues/24/events",
    "html_url": "https://github.com/kuizuo/blog/issues/24",
    "id": 1111300101,
    "node_id": "I_kwDOF7NJDM5CPRgF",
    "number": 24,
    "title": "Docusaurus配置Gitalk评论插件",
    "user": {
      "login": "kuizuo",
      "id": 61005888,
      "node_id": "MDQ6VXNlcjYxMDA1ODg4",
      "avatar_url": "https://avatars.githubusercontent.com/u/61005888?v=4",
      "gravatar_id": "",
      "url": "https://api.github.com/users/kuizuo",
      "html_url": "https://github.com/kuizuo",
      "followers_url": "https://api.github.com/users/kuizuo/followers",
      "following_url": "https://api.github.com/users/kuizuo/following{/other_user}",
      "gists_url": "https://api.github.com/users/kuizuo/gists{/gist_id}",
      "starred_url": "https://api.github.com/users/kuizuo/starred{/owner}{/repo}",
      "subscriptions_url": "https://api.github.com/users/kuizuo/subscriptions",
      "organizations_url": "https://api.github.com/users/kuizuo/orgs",
      "repos_url": "https://api.github.com/users/kuizuo/repos",
      "events_url": "https://api.github.com/users/kuizuo/events{/privacy}",
      "received_events_url": "https://api.github.com/users/kuizuo/received_events",
      "type": "User",
      "site_admin": false
    },
    "labels": [
      {
        "id": 3754161267,
        "node_id": "LA_kwDOF7NJDM7fw_Rz",
        "url": "https://api.github.com/repos/kuizuo/blog/labels/Gitalk",
        "name": "Gitalk",
        "color": "ededed",
        "default": false,
        "description": null
      },
      {
        "id": 3754411279,
        "node_id": "LA_kwDOF7NJDM7fx8UP",
        "url": "https://api.github.com/repos/kuizuo/blog/labels/blog",
        "name": "blog",
        "color": "ededed",
        "default": false,
        "description": null
      },
      {
        "id": 3754517867,
        "node_id": "LA_kwDOF7NJDM7fyWVr",
        "url": "https://api.github.com/repos/kuizuo/blog/labels/Docusaurus%E9%85%8D%E7%BD%AEGitalk%E8%AF%84%E8%AE%BA%E6%8F%92%E4%BB%B6",
        "name": "Docusaurus配置Gitalk评论插件",
        "color": "ededed",
        "default": false,
        "description": null
      }
    ],
    "state": "open",
    "locked": false,
    "assignee": null,
    "assignees": [],
    "milestone": null,
    "comments": 0,
    "created_at": "2022-01-22T06:47:34Z",
    "updated_at": "2022-01-22T06:47:34Z",
    "closed_at": null,
    "author_association": "OWNER",
    "active_lock_reason": null,
    "body": "https://kuizuo.cn/develop/Docusaurus配置Gitalk评论插件\n前言",
    "reactions": {
      "url": "https://api.github.com/repos/kuizuo/blog/issues/24/reactions",
      "total_count": 0,
      "+1": 0,
      "-1": 0,
      "laugh": 0,
      "hooray": 0,
      "confused": 0,
      "heart": 0,
      "rocket": 0,
      "eyes": 0
    },
    "timeline_url": "https://api.github.com/repos/kuizuo/blog/issues/24/timeline",
    "performed_via_github_app": null
  }
]
```

相关 api 文档 => [github docs](https://docs.github.com/cn/rest/reference/issues#comments)

也许后续可能考虑使用[octokit.js](https://github.com/octokit/octokit.js)来编写一个后台查询与删除的管理页。

## 最终效果

#### 评论页

![image-20220122164034147](https://img.kuizuo.cn/20220122164034.png)

#### issues 页面

![image-20220122163957435](https://img.kuizuo.cn/20220122163957.png)
