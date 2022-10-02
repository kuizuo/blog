---
slug: gitea-drone-practice
title: Gitea 与 Drone 实践
date: 2022-09-28
authors: kuizuo
tags: [git, gitea, drone]
keywords: [git, gitea, drone]
description: 使用 Gitea 搭建一个轻量级 git 私有仓库，并配置 Drone CI 来实现自动构建与部署。
---

之前搭建过 Gitlab，但是就只是搭建而已，并未实际使用，因为我大部分的代码还是存放在 [Github](https://github.com/kuizuo?tab=repositories) 上。

并且大部分项目都是在 [Vercel](https://vercel.com) 上运行的（Vercel 是真好用），但是最近国内访问 vercel 情况不容乐观，貌似被墙了呜呜。然后 Gitlab 的资源占用非常严重，几乎占用了一半的服务器性能，可 [点我](https://kuizuo.cn/gitlab-code-management-environment#运行状态) 查看运行状态。与此同时，随着很多私有项目越来越多，使用 git 私有仓库以及 Vercel 部署，肯定不如自建私有 git 服务和自有服务器部署使用体验来好。

于是就想搭建一个轻量级仓库，同时支持 CI/CD。经过一番的调研，决定使用 Gitea 和 Drone 作为解决方案。

<!-- truncate -->

## Gitea

[Gitea](https://gitea.io/zh-cn/ 'Gitea') 是一个开源社区驱动的轻量级代码托管解决方案，后端采用 [Go](https://golang.org/ 'Go') 编写，采用 [MIT](https://github.com/go-gitea/gitea/blob/master/LICENSE 'MIT') 许可证.

你可以在 [横向对比 Gitea 与其它 Git 托管工具](https://docs.gitea.io/zh-cn/comparison/#横向对比-gitea-与其它-git-托管工具 '横向对比 Gitea 与其它 Git 托管工具') 查看 gitea 与其他 git 工具的优势与缺陷。

### 安装

这里我选用 Docker 进行安装，安装文档可在[官方文档](https://docs.gitea.io/zh-cn/ '官方文档')中查看其他安装方式


```yaml title='docker-compose.yml'
version: '3'

networks:
  gitea:
    external: false

volumes:
  gitea:
    driver: local

services:
  server:
    image: gitea/gitea:1.17.1
    container_name: gitea
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
    networks:
      - gitea
    volumes:
      - gitea:/data
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    ports:
      - '10800:3000'
      - '2221:22'
```

根据自身需求配置 docker-compose.yml 内容。运行 `docker-compose up` 等待部署

服务器防火墙与云服务安全组都需要开放端口才可访问，`服务器ip:10800`，将会出现如下界面

![](https://img.kuizuo.cn/image_8ix-AMvt3t.png)

**因为修改配置相对比较麻烦，所以在首次安装的时候，请根据实际需求进行配置安装。**

### 修改配置

假设要修改其中的配置的话，gitea 的后台管理面板是无法直接修改的。需要到 `/data/gitea/conf/app.ini` 中修改，具体修改的配置 参阅 [自定义 Gitea 配置 - Docs](https://docs.gitea.io/zh-cn/customizing-gitea/ '自定义 Gitea 配置 - Docs')

:::caution 注意
必须完全重启 Gitea 以使配置生效。
:::
### 迁移仓库

从其他第三方 git 仓库迁移到 gitea，可以访问[https://git.kuizuo.cn/repo/migrate](https://git.kuizuo.cn/repo/migrate 'https://git.kuizuo.cn/repo/migrate') 来迁移仓库

![](https://img.kuizuo.cn/image_sRQV5hAKUh.png)

稍等片刻，取决于访问 github 仓库的速度。有可能还会迁移失败，就像下面这样。

![](https://img.kuizuo.cn/image_X9IpG2q36n.png)

所以可以申请访问令牌（Access Token），在 [New Personal Access Token](https://github.com/settings/tokens/new 'New Personal Access Token') 处创建。迁移成功后，如下图所示

![](https://img.kuizuo.cn/image_Rug0AmD8GE.png)

### 镜像仓库

很大部分时间，gitea 只能作为我的副仓库，或者说 github 的镜像仓库。

gitea 也提供镜像仓库的方案，官方文档[Repository Mirror](https://docs.gitea.io/en-us/repo-mirror/ 'Repository Mirror')

![](https://img.kuizuo.cn/image_Q5IaHnKCYJ.png)

## Drone

由于 Gitea 并没有内置 CI/CD（持续集成/持续部署） 的解决方案，所以需要配置第三方的，这里推荐使用 Drone CI。

Drone 是面向繁忙开发团队的自助服务持续集成平台。相对于常见的Jenkins，选中 Drone 的原因在于它非常简洁，不像 Jenkins 那样复杂，同时它拥有可以满足基本需求的能力，并且提供了许多实用的[插件](https://plugins.drone.io/)，如GitHub，Email，微信，钉钉等

### 安装 

由于我们使用了 gitea，所以 drone 中选择 gitea 来安装，这是官方文档 [Gitea | Drone](https://docs.drone.io/server/provider/gitea/ 'Gitea | Drone')，照着操作即可。

需要安装 Server 和 Runner，一个是 Drone 的服务，另一个用于检测 Git 记录，以重新构建项目。

这里贴下 drone 的 docker 配置（根据文档和自己部署的 git 服务配置来替换）。

```yaml title='server'
docker run \
  --volume=/var/lib/drone:/data \
  --env=DRONE_GITEA_SERVER=https://try.gitea.io \
  --env=DRONE_GITEA_CLIENT_ID=05136e57d80189bef462 \
  --env=DRONE_GITEA_CLIENT_SECRET=7c229228a77d2cbddaa61ddc78d45e \
  --env=DRONE_RPC_SECRET=super-duper-secret \
  --env=DRONE_SERVER_HOST=drone.company.com \
  --env=DRONE_SERVER_PROTO=https \
  --publish=80:80 \
  --publish=443:443 \
  --restart=always \
  --detach=true \
  --name=drone \
  drone/drone:2
```

```yaml title='runner'
docker run --detach \
  --volume=/var/run/docker.sock:/var/run/docker.sock \
  --env=DRONE_RPC_PROTO=https \
  --env=DRONE_RPC_HOST=drone.company.com \
  --env=DRONE_RPC_SECRET=super-duper-secret \
  --env=DRONE_RUNNER_CAPACITY=2 \
  --env=DRONE_RUNNER_NAME=my-first-runner \
  --publish=3000:3000 \
  --restart=always \
  --name=runner \
  drone/drone-runner-docker:1
```

查看连接情况

```bash
docker logs runner
```

执行完毕后，然后访问线上的 drone 服务，点击 CONTINUE 将会跳转到你的 Git 授权页面

![](https://img.kuizuo.cn/image_rUdNHPlB73.png)

点击应用授权，再次回到 drone，此时页面 Dashboard 列出了 gitea 的所有仓库（如果没有的话，可以点击右上角的 SYNC 来同步）。

![](https://img.kuizuo.cn/image_TXWZgDOhrQ.png)



## 实战

上述只是安装了，我们还需要编写 `.drone.yml` 配置文件来告诉 drone 我们要做什么，编写过程与 Github Action类似。相关文档: [Pipeline | Drone](https://docs.drone.io/pipeline/overview/ 'Overview | Drone')

### 部署前端项目

这里就选用 [antfu/vitesse](https://github.com/antfu/vitesse 'antfu/vitesse') 作为演示。这里省略 clone 仓库的步骤。进入到自己的 gitea 仓库，然后添加 `.drone.yml` 文件，内容如下：

```yaml
kind: pipeline
type: docker
name: ci

steps:
  - name: install & build
    image: node
    commands:
      - npm config set registry http://mirrors.cloud.tencent.com/npm/
      - npm i -g pnpm
      - pnpm i
      - pnpm run build

  - name: upload
    image: appleboy/drone-scp
    settings:
      host:
        from_secret: host
      username:
        from_secret: username
      password:
        from_secret: password
      port: 22
      command_timeout: 2m
      target: /www/wwwroot/${DRONE_REPO_OWNER}/${DRONE_REPO_NAME}
      source:
        - ./dist
```

这里对 `.drone.yml` 配置进行详解：

其中 build 这个不用多说，与 node 构建相关的，不过多介绍。

upload 则使用[appleboy/drone-scp](https://plugins.drone.io/plugins/scp 'appleboy/drone-scp')插件，可以将构建出来的文件通过发送到服务器指定位置。在这里 source 对应就是构建的文件，target 则是要移动的位置，这里的 `/www/wwwroot/${DRONE_REPO_OWNER}/${DRONE_REPO_NAME}` 对应本项目为 `/www/wwwroot/kuizuo/vitesse`。此外 ssh 的 host，username，password 或 key，都作为环境变量（私有变量的方式传递，这在 drone 的控制台中可以设置）。

由于每次构建可能需要删除原有的已部署的资源文件，那么可以使用 [appleboy/drone-ssh](https://plugins.drone.io/plugins/ssh) 插件来执行终端命令来删除，例如

```yaml
kind: pipeline
name: default

steps:
  - name: deploy
    image: appleboy/drone-ssh
    environment:
        DEPLOY_PATH:
            from_secret: /www/wwwroot/${DRONE_REPO_OWNER}/${DRONE_REPO_NAME}
    settings:
        host:
            from_secret: host
        username:
            from_secret: username
        password:
            from_secret: password
        port: 22
        command_timeout: 2m
        envs: [DEPLOY_PATH]
        script:
            - rm -rf $${DEPLOY_PATH}
```

具体就因人而异了，这里我仅作为演示。

大致介绍完毕（其实已经介绍差不多了），有关更多插件可以参阅 [drone 插件](https://plugins.drone.io 'drone 插件')。这里开始演示，进入 drone 页面，找到仓库，默认情况下，所有仓库都处于未激活状态。

![](https://img.kuizuo.cn/image_6XBrsAY8VE.png)

点击 `ACTIVATE REPOSITORY` 根据选项选择，点击右上角的`NEW BUILD`选择分支，添加 drone 环境变量（私有变量），即上面的 from_secret 后面的内容（host，username，password），即可开始运行。

![](https://img.kuizuo.cn/image_PAM6QQS1V_.png)

静等 PIPELINE 执行完毕，结果如下

![image-20220928152635955](https://img.kuizuo.cn/image-20220928152635955.png)

此时打开宝塔，跳转到指定目录下，就可以看到构建的内容都已经放到指定位置了

![image-20220928152725853](https://img.kuizuo.cn/image-20220928152725853.png)

这时候只需要配置下 nginx，就能将页面展示到公网上，这里就不在这里赘述。当完成上述配置完毕后，每次只需要 pull request，drone 就会自动拉取 gitea 的代码，并开始执行`.drone.yml`中的任务。

### 部署 nest 项目

TODO。。。

## 参考文章

[【CI/CD】搭建 drone 服务，构建前端 cicd 工作流，实现博客的自动化打包并部署 - 掘金 (juejin.cn)](https://juejin.cn/post/7073380337766072350 '【CI/CD】搭建drone服务，构建前端cicd工作流，实现博客的自动化打包并部署 - 掘金 (juejin.cn)')

[单机部署 CI/CD 进阶版：宝塔+gitea+drone | Laravel China 社区 (learnku.com)](https://learnku.com/articles/71333)
