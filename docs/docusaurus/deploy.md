---
id: docusaurus-deploy
slug: /docusaurus-deploy
title: 部署
authors: kuizuo
---

我之前使用 [Vercel](https://vercel.com) 一把梭，无需任何配置。这样我就只需要专注输出内容即可。这是我当时使用 Vercel 部署的文章 [Vercel 部署个人博客](/blog/vercel-deploy-blog)

但如今，`vercel.app` 被 DNS 污染，即被墙了，导致国内无法访问，虽然使用有自己的域名解析到 Vercel 上也可能访问，但被墙了，也就意味着国内 DNS 的解析速度必然有所下降，导致站点访问速度有所下降。

加上我想有更好的访客体验，于是我决定采用国内国外不同的解析方式来加快访问。

首先在线路类型中，分别针对境内和境外做了不同的记录值，境内使用国内的 CDN 服务，而境外就使用 Vercel。

![image-20221204161431863](https://img.kuizuo.cn/image-20221204161431863.png)

这样我国内访问就是访问国内的 CDN，访问国外访问就是 Vercel 的 CDN，这样针对不同的地区的网络都能有一个不错的访问速度，可以到 [Ping.cn:网站测速-ping 检测](https://www.ping.cn/) 中测试测试你的站点访问速度如何。

以下是我的网站测速结果，也可通过访问 [kuizuo.cn 在全国各地区网络速度测试情况-Ping.cn](https://www.ping.cn/http/kuizuo.cn) 在线查看

![image-20221204161146327](https://img.kuizuo.cn/image-20221204161146327.png)

果然，花钱了就是不一样。

## 持续集成

由于 Vercel 能够自动拉取仓库代码，并自行构建部署，因此通常什么配置都不需要。

由于代码提交到代码仓库(github)，则需要借用 CI 服务来帮助我们完成这些任务，这里我使用了 [Github Action](https://github.com/marketplace) 来帮助我构建，构建记录可以在 [Actions · kuizuo/blog](https://github.com/kuizuo/blog/actions) 中查看。以下是我的配置文件

```yaml title='.github/workflows/ci.yml' icon='logos:github-actions'
name: CI

on:
  push:
    branches:
      - main

jobs:
  build-and-deploy:
    runs-on: ${{ matrix.os }}

    strategy:
      matrix:
        os: [ubuntu-latest] # macos-latest, windows-latest
        node: [18]

    steps:
      - uses: actions/checkout@v4

      - name: Set node version to ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}

      - run: corepack enable

      - name: Setup
        run: npm i -g @antfu/ni

      - name: Install
        run: nci

      - name: Build
        run: nr build

      - name: SSH Deploy
        uses: easingthemes/ssh-deploy@v4.1.10
        env:
          SSH_PRIVATE_KEY: ${{ secrets.SSH_PRIVATE_KEY }}
          ARGS: '-avzr --delete'
          SOURCE: 'build'
          REMOTE_HOST: ${{ secrets.REMOTE_HOST }}
          REMOTE_USER: 'root'
          TARGET: '/opt/1panel/apps/openresty/openresty/www/sites/kuizuo.cn/index'
```

等待 CI 将最终构建的产物通过 rsync 放到自己的服务器上，便完成了整套部署的流程。

当一切都配置好了之后，我只需要将代码推送到远程仓库上，Github Action 与 Vercel 分别完成它们所该做的任务。等待片刻，再次访问站点，刚刚提交的代码就成功生效了。

## 没有域名和服务器该怎么部署？

当然了上述只是我的配置方案，有许多伙伴可能没有自己的域名或者自己的服务器，就想着白嫖，那么这里目前我只能推荐 [Netlify](https://www.netlify.com/)，然后通过 netlify 的二级域名如 kuizuo-blog.netlify.app 来进行访问。

我个人还是非常建议去弄一个属于自己的域名，通过 Vercel 的自定义域名就可以访问。并且由于自己的域名解析的不是大陆的服务器（Vercel 的服务器就不是国内大陆的），因此无需备案这一更繁琐的步骤。
