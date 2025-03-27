---
id: git-push-multiple-remote-repos
slug: git-push
title: git 推送多个远程仓库
date: 2023-11-09
authors: kuizuo
tags: [git]
keywords: [git]
---

<!-- truncate -->

核心命令

```bash
git remote set-url --add origin 远程仓库地址
```

如：`git remote set-url --add origin https://git.kuizuo.cn/kuizuo/blog.git`

此时打开 `.git/config`，可以看到这样的配置

```bash {4}
[remote "origin"]
    url = https://github.com/kuizuo/blog.git
    fetch = +refs/heads/*:refs/remotes/origin/*
    url = https://git.kuizuo.cn/kuizuo/blog.git
```

上述命令 git 配置添加新的 url 记录。也可手动添加、修改。

`git push origin --all` 推送至所有远程仓库
