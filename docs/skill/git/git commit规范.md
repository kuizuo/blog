---
id: git-conmit-specification
slug: git-conmit-specification
title: git commit规范
date: 2021-08-31
authors: kuizuo
tags: [git, commit]
keywords: [git, commit]
---

<!-- truncate -->

提交规范主要是为了让开发者提交完整的更新信息，方便查阅。

目前最为流行的提交信息规范来自于 Angular 团队。

规范中，主要就是要求提交内容要进行分类并填写内容，更为严格的规定是要求标注开发模块，整个语法如下

```bash
type(scope?): subject  #scope is optional; multiple scopes are supported (current delimiter options: "/", "\" and ",")
```

| type     | commit 的类型                                            |
| -------- | -------------------------------------------------------- |
| feat     | 新功能、新特性                                           |
| fix      | 修改 bug                                                 |
| perf     | 更改代码，以提高性能                                     |
| refactor | 代码重构（重构，在不影响代码内部行为、功能下的代码修改） |
| docs     | 文档修改                                                 |
| style    | 代码格式修改, 注意不是 css 修改（例如分号修改）          |
| test     | 测试用例新增、修改                                       |
| build    | 影响项目构建或依赖项修改                                 |
| revert   | 恢复上一次提交                                           |
| ci       | 持续集成相关文件修改                                     |
| chore    | 其他修改（不在上述类型中的修改）                         |
| release  | 发布新版本                                               |
| workflow | 工作流相关文件修改                                       |

以下是一些示例：

| commit message                     | 描述                      |
| ---------------------------------- | ------------------------- |
| chore: init                        | 初始化项目                |
| chore: update deps                 | 更新依赖                  |
| chore: wording                     | 调整文字（措词）          |
| chore: fix typos                   | 修复拼写错误              |
| chore: release v1.0.0              | 发布 1.0.0 版本           |
| fix: icon size                     | 修复图标大小              |
| fix: value.length -> values.length | value 变量调整为 values   |
| feat(blog): add comment section    | blog 新增评论部分         |
| feat: support typescript           | 新增 typescript 支持      |
| feat: improve xxx types            | 改善 xxx 类型             |
| style(component): code             | 调整 component 代码样式   |
| refactor: xxx                      | 重构 xxx                  |
| perf(utils): random function       | 优化 utils 的 random 函数 |
| docs: xxx.md                       | 添加 xxx.md 文章          |

更多示例可以参考主流开源项目的 commit。

## 检查 commit 规范

要检查 commit message 是否符合要求，可以使用 [commitlint](https://github.com/conventional-changelog/commitlint) 工具，并配合 [husky](https://github.com/typicode/husky) 对每次提交的 commit 进行检查。

当然规范不是强求，但 commit message 一定要能简要说明本次代码的改动主要部分，有利于他人与自己后期查看代码记录。
