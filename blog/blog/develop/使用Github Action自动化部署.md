---
slug: use-github-action-to-auto-deploy
title: 使用Github Action自动化部署
date: 2022-05-11
authors: kuizuo
tags: [github, git]
keywords: [github, git]
---

如果有写过项目的经历，就免不了将代码上传到服务器上，安装依赖，然后输入启动命令的步骤。但是有的项目往往需要经常性的改动，如果还是照着上面的方式进行部署的话。先不说这样操作的效率，操作个几次就想罢工了。并且上面这样操作的往往容易误操作。而 Github Actions 正是该问题的良药。

<!-- truncate -->

## 介绍

Github Actions 是 Github 提供的免费自动化构建实现，特别适用于持续集成和持续交付的场景，它具备自动化完成许多不同任务的能力，例如构建、测试和部署等等。

## 概念

在进行操作前，先对 Github Actions 基础知识进行补充，具体可查看 [GitHub Actions 入门教程 阮一峰](https://www.ruanyifeng.com/blog/2019/09/getting-started-with-github-actions.html)

可以在 [GitHub Marketplace · Actions to improve your workflow](https://github.com/marketplace?type=actions) 中找到所有的 Actions。

## 实例：将 VIte 项目发布到 GitHub Pages

第一步：创建一个 Vite 工程，可在[官网](https://cn.vitejs.dev/guide/#scaffolding-your-first-vite-project)中查看如何安装

```
pnpm create vite
```

选择对应的项目名（vite-project）与模板（vue-ts）

第二步：打开`package.json`文件，加一个`homepage`字段，表示该应用发布后的根目录（参见[官方文档](https://create-react-app.dev/docs/deployment#building-for-relative-paths)）。

```
"homepage": "https://[username].github.io/vite-project",
```

上面代码中，将`[username]`替换成你的 GitHub 用户名。

第三步：在这个仓库的`.github/workflows`目录，生成一个 workflow 文件，名字可以随便取，这个示例是`ci.yml`。

workflow 文件如下

```yml
name: Build and Deploy
on:
  push:
    branches:
      - master
jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Install and Build
        run: |
          yarn install
          yarn run build

      - name: Deploy
        uses: peaceiris/actions-gh-pages@v3
        with:
          personal_token: ${{ secrets.ACCESS_TOKEN }}
          publish_dir: ./dist
```

上面这个 workflow 文件的要点如下

1. 整个流程在`master`分支发生`push`事件时触发。
2. 只有一个`job`，运行在虚拟机环境`ubuntu-latest`。
3. 第一步是获取源码，使用的 action 是`actions/checkout`。
4. 第二步是安装依赖与构建，`yarn install`和`yarn run build`
5. 第三步是部署到 Github Page 上，使用的 action 是 [peaceiris/actions-gh-pages@v3](https://github.com/marketplace/actions/github-pages-action)。其中需要设置 secrets.ACCESS_TOKEN

第四步：将项目上传置 Github 仓库中，

该 peaceiris/actions-gh-pages 支持三种 Token，这里使用 personal_token，其生成教程在[官方文档](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)中有详细图文，这里就不贴其生成的图了。**不过记得权限过期以及勾选上 workflow**

:::tip Tip

token 只会在生成的时候显示一次，如需要再次显示，则可以点击，但使用此令牌的任何脚本或应用程序都需要更新！

:::

然后在**Settings -> Secrets -> Actions 中 New repository secret**中便可添加 secret。

![image-20220511122017247](https://img.kuizuo.cn/image-20220511122017247.png)

这时候只要一调用 git push，就会触发对应的 workflows 文件配置。点击 Actions 便可看到 jobs 工作。

![image-20220511122420135](https://img.kuizuo.cn/image-20220511122420135.png)

此时访问https://kuizuo.github.io/vite-project就可呈现vite项目（不过我已经把仓库给关闭了），但进入会白屏，控制台提示

![image-20220511122914534](https://img.kuizuo.cn/image-20220511122914534.png)

很显然，需要静态资源请求的路径错了，正确的应该是https://kuizuo.github.io/vite-project/assets/index.2435d274.js，根据Vite中的[构建生产版本](https://www.vitejs.net/guide/build.html#public-base-path) 通过命令行参数 `--base=/vite-project/`

稍加操作在 Install and Build 加上 base 参数

```
      - name: Install and Build
        run: |
          yarn install
          yarn run build --base=/vite-project/
```

git push 后，稍等片刻再次访问便可得到如下页面

![image-20220511125536189](https://img.kuizuo.cn/image-20220511125536189.png)

## FTP发布到自有服务器上

那么现在在 Github Page 上搭建好了，但还要将编译后的文件还可以通过 FTP 协议添加自己的服务器上，这里我就以我的博客为例。

在服务器中开启 FTP，并添加一个用户名,密码以及根目录(这里我问选择为项目目录)

workflow 要做的就是新建一个 steps，这里选用 [FTP-Deploy-Action](https://github.com/SamKirkland/FTP-Deploy-Action)，以下是我的完整配置内容

```yml
name: FTP Deploy

on: [push]

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

      - name: FTP Deploy
        uses: SamKirkland/FTP-Deploy-Action@4.0.0
        with:
          server: ${{ secrets.ftp_server }}
          username: ${{ secrets.ftp_user }}
          password: ${{ secrets.ftp_pwd }}
          local-dir: ./build/
          server-dir: ./
```

相信第一个实例中的 workflow 应该已经明白了，其中 ftp_server，ftp_user，ftp_pwd 都是私密信息，所以需要 New repository secret 设置这三个变量。

但由于 build 下存在大量文件夹与文件，所以 FTP 速度上传速度堪忧，最终耗时 17 minutes 38.4 seconds。这里只是作为 FTP 演示。

## SCP发布到自有服务器上

FTP 传输文件着实过慢，所以可以通过 SCP 的方式来传输文件，这里用到了[ssh deploy · Actions](https://github.com/marketplace/actions/ssh-deploy)，以下是示例

```yaml
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

其中 **PRIVATE_KEY** 为服务器SSH登录的私钥，**REMOTE_HOST** 就是服务器的ip地址。当然，这些参数也都作为私密信息，也是要通过New repository secret来设置的。

## 总结

从上面的演示便可看出 Github Actions 的强大，但其实我挺早之前就了解到它能做这些事情，但迟迟没有动手尝试一番，因为这些自动化操作用人工也是能完成的。也许当时的我认为，用人工所花费的时间远比自动化操作的学习时间来的长，可又随着自己的个人应用增加，每次都需要手动发布，而此时前者的时间已远远大于后者，所以才会想去学习。

明知该技术是一定会接触的，为何不趁现在去了解学习呢？
