---
title: git修改默认分支main
date: 2021-08-04
tags:
 - git
---


<!-- truncate -->
## 前言

GitHub 官方表示，从2020 年 10 月 1 日起，在该平台上创建的所有新的源代码仓库将默认被命名为 "main"，而不是原先的"master"。值得注意的是，现有的存储库不会受到此更改影响。

也就是现在从github初始化的项目都是main分支，然而在此之前安装的git默认分支为master，本地使用git创建项目都是master，通过如下命令可更改默认分支的名字

## 命令

- 修改默认分支为 `main` 分支

```
git config --global init.defaultBranch main
```

- 修改当前项目的分支为 `main`

```
git branch -M main
```

要更改为其他名字 只需把main替换即可

### 要求

Git 版本为 **v2.28** 或更高 查看版本 `git --version`