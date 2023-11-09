---
id: github-apps-example
slug: github-apps-example
title: github apps示例
date: 2021-10-01
authors: kuizuo
tags: [github, app]
keywords: [github, app]
---

<!-- truncate -->

### Github Dependabot

介绍：[About Dependabot security updates - GitHub Docs](https://docs.github.com/cn/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates)

简单说就是一个能够自动更新项目依赖，确保仓库代码依赖的包和应用程序一直处于最新版本的机器人。

将 `dependabot.yml` 配置文件放入仓库的 `.github` 目录中即可开启。当然也可以到 `Insights` => `Dependency graph` => `Dependabot` 中开启。如下图

![image-20221001171946879](https://img.kuizuo.cn/image-20221001171946879.png)

然后创建你的配置文件，默认内容如下

![image-20221001172149673](https://img.kuizuo.cn/image-20221001172149673.png)

其中要修改 package-ecosystem 配置，也就是包管理器，比如node就用npm，python就用pip。可以在 [About Dependabot version updates - GitHub Docs](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/about-dependabot-version-updates#supported-repositories-and-ecosystems) 中查看。

然后配置完毕后，根据时间周期，就会自动检测依赖更新，并创建一个pull request 请求，仓库拥有者根据实际需要合并即可。

### [Stale](https://github.com/marketplace/stale)

可在一段时间不活动后关闭废弃的问题。即**关闭长时间未回复的issues**。

### [Imgbot](https://github.com/marketplace/imgbot)

Imgbot是一个友好的机器人，可以优化您的图像并节省您的时间。优化的图像意味着在不牺牲质量的情况下减小文件大小。

### [giscus](https://github.com/marketplace/giscus)

由 GitHub 讨论提供支持的评论系统。让访问者通过GitHub在您的网站上发表评论和反应！

### [WakaTime](https://github.com/marketplace/wakatime)

从编程活动中自动生成的生产力指标、见解和时间跟踪。

### [wxwork](https://github.com/marketplace/wxwork-github-webhook)

Github 企业微信群机器人，无需配置轻松集成 Github 与 企业微信。