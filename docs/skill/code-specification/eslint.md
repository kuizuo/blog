---
id: eslint
slug: /eslint
title: eslint
authors: kuizuo
keywords: ['code-specification', 'eslint']
---

ESLint 是一种用于识别和报告 ECMAScript/JavaScript 代码中发现的模式的工具，目的是使代码更加一致并避免错误。

[Getting Started with ESLint](https://eslint.org/docs/latest/user-guide/getting-started)

## eslint-config

这里强烈推荐 [antfu/eslint-config](https://github.com/antfu/eslint-config)，以及大佬的文章 [Why I don't use Prettier (antfu.me)](https://antfu.me/posts/why-not-prettier)

这份 eslint 配置对于 ts 与 vue 已经足够完整，如果还有其他需求，可自行添加 rule 或使用[overrides](https://eslint.org/docs/latest/user-guide/configuring/configuration-files#how-do-overrides-work)。

## 在 Vscode 中集成 ESlint 插件

- 在 VScode 插件市场安装 [ESLint 插件](https://marketplace.visualstudio.com/items?itemName=dbaeumer.vscode-eslint)

- 开启代码保存时自动执行 ESLint 修复功能(全局设置)

```
  "editor.codeActionsOnSave": {
    "source.fixAll": false,
    "source.fixAll.eslint": true,
    "source.organizeImports": false
  },
```

- 工作区示例如下

```json title='.vscode/settings.json'
{
  "prettier.enable": false,
  "editor.formatOnSave": false,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  }
}
```

## 在 WebStorm 中集成 ESLint 插件

> 由于 WebStorm 自动集成 ESLint，所以我们无需安装

- 进入 WebStorm 配置 ESLint 自动修复

![image-20220701081021965](https://tva1.sinaimg.cn/large/e6c9d24egy1h3r3vxs790j215p0u00vk.jpg)

## 注意事项

由于 eslint 配置相对繁琐，所以很多时候编辑器的 eslint 可能都没有生效，具体看编辑器下方状态栏或者日志输出查看ESLint状态。如果为警告（黄色感叹号）或者错误（红色），那么ESLint就是没配置好，可能缺少某些依赖文件或是配置文件写错了。

![](https://img.kuizuo.cn/image-20221002163239434.png)
