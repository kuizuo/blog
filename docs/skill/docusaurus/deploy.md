---
id: docusaurus-deploy
slug: /docusaurus-deploy
title: 部署
authors: kuizuo
---

我之前使用 [Vercel](https://vercel.com) 一把梭，无需任何配置，我只需要专注输出内容即可，这是我当时使用 Vercel 部署的文章 [Vercel 部署个人博客](/blog/vercel-deploy-blog)

但如今，`vercel.app` 被 DNS 污染，即被墙了，导致国内无法访问，虽然使用有自己的域名解析到 Vercel 上也可能访问，但被墙了，也就意味着国内 DNS 的解析速度必然有所下降，从而导致站点访问速度有所下降。

加上我想有更好的访客体验，于是我决定采用国内国外不同的解析方式来加快访问。

首先在线路类型中，分别针对境内和境外做了不同的记录值，境内使用国内的 CDN 服务，而境外就使用 Vercel。

![image-20221204161431863](https://img.kuizuo.cn/image-20221204161431863.png)

这样我国内访问就是访问国内的 CDN，访问国外访问就是 Vercel 的 CDN，这样针对不同的地区的网络都能有一个不错的访问速度，可以到 [Ping.cn:网站测速-ping 检测](https://www.ping.cn/) 中测试测试你的站点访问速度如何。

以下是我的网站测速结果，也可通过访问 [kuizuo.cn 在全国各地区网络速度测试情况-Ping.cn](https://www.ping.cn/http/kuizuo.cn) 在线查看

![image-20221204161146327](https://img.kuizuo.cn/image-20221204161146327.png)

果然，花钱了就是不一样。

## 持续集成

国外的好理解，有 Vercel 能够自动拉取仓库代码，并自行构建部署，可国内呢？

这里我是借助了 [Github Action](https://github.com/marketplace) 来帮助我构建，构建记录可以在 [Actions · kuizuo/blog](https://github.com/kuizuo/blog/actions) 中查看。以下是我的配置文件

```yaml title='.github/workflows/ci.yml'
name: ci

on:
  push:
    branches:
      - main

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Use Node.js 16
        uses: actions/setup-node@v3
        with:
          node-version: '16.x'

      - name: Build Project
        run: |
          yarn install
          yarn run build

      - name: SSH Deploy
        uses: easingthemes/ssh-deploy@v2.2.11
        env:
          SSH_PRIVATE_KEY: ${{ secrets.PRIVATE_KEY }}
          ARGS: '-avzr --delete'
          SOURCE: 'build'
          REMOTE_HOST: ${{ secrets.REMOTE_HOST }}
          REMOTE_USER: 'root'
          TARGET: '/www/wwwroot/blog'
```

Github Action 帮我构建好之后，并通过 ssh 连接我的服务器，将构建好的静态文件替换到我的 blog 存放的位置上。

一切都配置好了之后，我只需要将代码推送到 Github 仓库上，Github Action 与 Vercel 分别完成它们所该做的任务，等待片刻，再次访问站点，刚刚提交的代码就成功生效了。

## 没有域名和服务器该怎么部署？

当然了上述只是我的配置方案，有许多伙伴可能没有自己的域名或者自己的服务器，就想着白嫖，那么这里目前我只能推荐 [Netlify](https://www.netlify.com/)。

我个人还是非常建议去弄一个属于自己的域名，通过 Vercel 的自定义域名就可以访问，并且无需像上述那样搞特别复杂的配置。由于自己的域名解析的不是大陆的服务器（Vercel 的服务器就不是国内大陆的），所以也就无需备案。
