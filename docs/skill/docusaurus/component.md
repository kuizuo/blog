---
id: docusaurus-component
slug: /docusaurus-component
title: 自定义组件
authors: kuizuo
---

初始化的一个 docusaurus 项目就已经有预留好的的组件，例如博客布局，标签页归档页等等。但是这些组件的样式可能不满你的审美，或者是想增加在这些主题组件中增加点东西。那么就需要用到 [Swizzle](https://docusaurus.io/zh-CN/docs/swizzling)

## 主题组件

在 docusaurus 中的主题组件存放在 **@docusaurus/theme-classic/theme** 下，如果想要覆盖某个组件的话可以在 src/theme 目录下创建与之对应文件路径结构相同的文件。

像下面这样

```
website
├── node_modules
│   └── @docusaurus/theme-classic
│       └── theme
│           └── Navbar.js
└── src
    └── theme
        └── Navbar.js
```

每当导入 `@theme/Navbar` 时，`website/src/theme/Navbar.js` 都会被优先载入。

关于*分层架构*可看[客户端架构 | Docusaurus](https://docusaurus.io/zh-CN/docs/advanced/client)

## swizzle 组件

要输出所有 `@docusaurus/theme-classic` 组件的总览，可以运行：

```sh
yarn run swizzle @docusaurus/theme-classic -- --list
```

不过我更倾向于直接在 `node_modules/@docusaurus/theme-classic/src/theme` 查看所有组件。

这里以归档页举例，官方的归档页面组件是 `theme/BlogArchivePage`

有两种方式可以完成自定义组件：[弹出组件](https://docusaurus.io/zh-CN/docs/swizzling#ejecting)或者[包装组件](https://docusaurus.io/zh-CN/docs/swizzling#wrapping)

例如弹出组件，可以执行以下[命令](https://docusaurus.io/zh-CN/docs/cli#docusaurus-swizzle)：

```sh
yarn run swizzle @docusaurus/theme-classic BlogArchivePage -- --eject --typescript
```

这样会创建 `src/theme/BlogArchivePage/index.tsx`，也就是归档页面的代码，而要做的就是修改代码，实现自己所需的样式与功能。

不过这样获取到的只是index.tsx文件，有可能还存在子组件。所有我一般的做法是在 `node_modules/@docusaurus/theme-classic/src/theme` 中找到组件所在文件夹，然后将整个文件夹复制到 `src/theme` 下。这样能得到就是最原始的ts文件，同时所能修改的地方也就越多，更方便的个性化。

:::caution

**但是**，在使用自定义组件的时候，有些主题组件可能会存在一定**风险**。尤其是在升级 Docusaurus 变得更困难，因为如果接收的属性发生变化，或内部使用的主题 API 发生变化，有可能就会导致页面渲染失败。

就比如我在将 docusaurus 升级到 2.0.0 正式版的时候就出现页面错误，原因是 [plugin-content-blog](https://docusaurus.io/zh-CN/docs/api/plugins/@docusaurus/plugin-content-blog) 在传递给组件的数据发生了变动，导致数据无法解析，自然而然页面就渲染失败。

:::

:::info

当然，如果不升级依赖也确实不会有问题，但谁能保证新版本的一些特性不吸引使用者去升级呢？

所以在自定义组件的时候，升级依赖后就可能需要维护一定的代码。要做的是重新 swizzle 一份最新的文件，然后去比对变化，最终排查问题。

:::
