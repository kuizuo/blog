---
id: husky
slug: /husky
title: husky
authors: kuizuo
keywords: ['code-style', 'husky']
---

为了确保只有合格的代码才能够提交到仓库。需要配置自动化脚本，确保代码在提交前通过了代码验证工具的检验。

实际上 git 本身就设计了生命周期钩子来完成这个任务。但是设置过程比较复杂。所以通常情况下会使用 husky 来简化配置。

[Husky](https://typicode.github.io/husky/#/)

[Git - githooks](https://git-scm.com/docs/githooks)

```bash
pnpm i husky -D
```

会创建一个 npm script

```
npm set-script prepare "husky install"
```

## githooks

### 在 commit 提交前执行 lint 代码校验

执行下方命令，以添加生命周期钩子：

```sql
npx husky add .husky/pre-commit "pnpm lint"
```

会创建 `.husky/pre-commit` 文件，其内容如下

```bash title='.husky/pre-commit'
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

pnpm lint
```

在每次提交时，都将会执行 lint 脚本来检查代码。

### 在 push 之前通过单元测试

不过更多的做法都是用 **github action** 配置 CI 在虚拟机上跑测试，而不是本地测试。（故这步可省略）

执行下方命令，以添加生命周期钩子：

```bash
npx husky add .husky/pre-push "pnpm test"
```

### 提交时自动检查 commit 信息是否符合要求

[commitlint - Lint commit messages](https://commitlint.js.org/#/?id=getting-started)

安装

```bash
pnpm i -g @commitlint/cli @commitlint/config-conventional
```

```bash
echo "module.exports = {extends: ['@commitlint/config-conventional']}" > commitlint.config.js
```

:::caution 注意

windows 系统请勿使用上行命令，否则会导致编码不是 UTF-8。建议直接复制文本内容到 `commitlint.config.js`

```javascript title='commitlint.config.js'
module.exports = {extends: ['@commitlint/config-conventional']};
```

:::

将 commitlint 脚本添加到 githooks 中， 让每次提交前都验证信息是否正常。

```bash
npx husky add .husky/commit-msg "npx --no-install commitlint --edit "$1""
```

其内容如下

```bash title='.husky/commit-msg'
#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

npx --no-install commitlint --edit "$1"
```

测试 commit 提交 `echo 'foo: bar' | commitlint` 将会报错，不符合 commit msg 规范。

```
echo 'foo: bar' | commitlint
⧗   input: foo: bar✖   type must be one of [build, chore, ci, docs, feat, fix, perf, refactor, revert, style, test] [type-enum]

✖   found 1 problems, 0 warnings
ⓘ   Get help: https://github.com/conventional-changelog/commitlint/#what-is-commitlint
```
