---
id: editorconfig
slug: /editorconfig
title: editorconfig
authors: kuizuo
keywords: ['code-specification', 'editorconfig']
---

[Editorconfig](https://editorconfig.org/) 有助于跨各种编辑器和 IDE 为处理同一项目的多个开发人员维护一致的编码样式。

## 使用 ESLint 做代码 lint，那么为什么还要使用 .editorconfig 呢？

- ESLint 确实包含 .editorconfig 中的一些属性，如缩进等，但并不全部包含，如 .editorconfig 中的 insert_final_newline 属性 Eslint 就没有。Eslint 更偏向于对语法的提示，如定义了一个变量但是没有使用时应该给予提醒。而 .editorconfig 更偏向于代码风格，如缩进等。
- ESLint 仅仅支持对 js 文件的校验，而 .editorconfig 不光可以检验 js 文件的代码风格，还可以对 .py（python 文件）、.md（markdown 文件）进行代码风格控制。

> 根据项目需要，Eslint 和 .editorconfig 并不冲突，同时配合使用可以使代码风格更加优雅。

## 安装 EditorConfig

[EditorConfig for VS Code](https://marketplace.visualstudio.com/items?itemName=EditorConfig.EditorConfig)

创建 `.editorconfig`，示例内容如下

```editorconfig title='.editorconfig'
# http://editorconfig.org

root = true

[*]
charset = utf-8
indent_style = space
indent_size = 2
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
quote_type = single

[*.md]
insert_final_newline = false
trim_trailing_whitespace = false
```