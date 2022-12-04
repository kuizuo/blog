---
id: docusaurus-comment
slug: /docusaurus-comment
title: 评论服务
authors: kuizuo
---

这里推荐两种评论服务

Giscus：基于GitHub Discussions，对程序员相对友好，评论信息提示通过github邮箱发送。

Waline：需要搭建后端服务与数据库服务，提供评论与浏览量服务，可拓展性强。

## [giscus](https://giscus.app)

之前的评论使用的是 gitalk，但是那个是基于 github issue 的，并且 issue 不能关闭，每次打开仓库的时候都会看到几十个 issue，特别不友好。

所以后面就考虑换成 [giscus](https://giscus.app/zh-CN)，由 [GitHub Discussions](https://docs.github.com/en/discussions) 驱动的评论系统。首先要确保以下几点：

1. **此仓库是[公开的](https://docs.github.com/en/github/administering-a-repository/managing-repository-settings/setting-repository-visibility#making-a-repository-public)**，否则访客将无法查看 discussion（并不需要一定是博客的项目，随便一个仓库都可以）。
2. **[giscus](https://github.com/apps/giscus) app 已安装**否则访客将无法评论和回应。
3. **Discussions** 功能已[在你的仓库中启用](https://docs.github.com/en/github/administering-a-repository/managing-repository-settings/enabling-or-disabling-github-discussions-for-a-repository)。

本博客已经内置好评论组件 `src/component/Comment`，所以只需要在 docusaurus.config.js 中设置 giscus 的配置即可。

### 配置giscus

打开 [giscus](https://giscus.app/) 官网，填写完对应的信息后，可以得到一个已经配置好的`<script>`标签

```html
<script src="https://giscus.app/client.js"
        data-repo="kuizuo/blog"
        data-repo-id="MDEwOlJlcG9zaXRvcnkzOTc2MjU2MTI="
        data-category="General"
        data-category-id="DIC_kwDOF7NJDM4CPK95"
        data-mapping="title"
        data-strict="0"
        data-reactions-enabled="1"
        data-emit-metadata="0"
        data-input-position="top"
        data-theme="light"
        data-lang="zh-CN"
        crossorigin="anonymous"
        async>
</script>
```

复制 `data-repo`, `data-repo-id`, `data-category` 和  `data-category-id` 填写到 `docusaurus.config.js` 中即可，

```javascript title='docusaurus.config.js'
giscus: {
    repo: 'kuizuo/blog',
    repoId: 'MDEwOlJlcG9zaXRvcnkzOTc2MjU2MTI=',
    category: 'General',
    categoryId: 'DIC_kwDOF7NJDM4CPK95',
    mapping: 'title',
    lang: 'zh-CN',
},
```

:::info

如果不替换的话，评论的信息都将会在我的 Discussions 下😂

:::

## [waline](https://github.com/walinejs/waline)

目前比较流行的博客评论系统还有 waline，它可以提供评论与浏览量服务，由于需要搭配后端服务与数据库服务，所以在配置方面会比 giscus 来的麻烦，但它无需 github Discussions，所以也是绝大多数博客作者的标配。

关于如何配置，参见官方 [快速上手 | Waline](https://waline.js.org/guide/get-started.html)