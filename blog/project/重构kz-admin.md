---
slug: refactor-kz-admin
title: 重构kz-admin
date: 2022-11-07
authors: kuizuo
tags: [project, admin]
keywords: [project, admin]
description: kz-admin 是一个基于 NestJs + TypeScript + TypeORM + Redis + MySql + Vben Admin 编写的一款前后端分离的权限管理系统
image: /img/project/kz-admin.png
---

![](https://img.kuizuo.cn/logo_irKdpu5Epv.png)

> kz-admin 使用 NestJs + TypeScript + TypeORM + Redis + MySql + Vben Admin
> 等技术栈，并采用 monorepo 管理项目，希望这个项目在 ts 全栈的路上能够帮助到你。

详细介绍可以参见 [kz-admin后台管理系统](/kz-admin)

## 为何重构

前段时间基于我的 [kz-admin](https://github.com/kuizuo/kz-admin "kz-admin")
模板写了一个link-admin的项目（可以访问 [link.kuizuo.cn](http://link.kuizuo.cn/ "link.kuizuo.cn") 在线体验，账号 admin，密码a123456），是一个“一次性”充值链接管理系统，具体自行体验即可（项目未开源）。

该项目有前端管理页面，后端服务，和一个链接使用页面，共三个项目。

每次启动时候，都需要进入到对应项目下，打开终端，输入命令。要么使用`npm-run-all` 来批量执行 dev 与 build 命令。

想到后续项目的应用场景大概率也可能是多项目的，于是就准备使用 turborepo 将项目重构为 monorepo 管理，将前后端项目都统一放到一个仓库中，并且将 nestjs 版本升级到 v9，顺便在完善一下api接口文档，并提供 [ApiFox](https://www.apifox.cn/ "ApiFox") 文档。

<!-- truncate -->

## monorepo重构

monorepo的重构相对简单，首先使用 [Turborepo](https://turbo.build/repo/docs/getting-started/create-new "Turborepo") 新建一个 monorepo 的仓库，目录结构如下

![](https://img.kuizuo.cn/image_Svd1WZKBdf.png)

将 packages 与 apps 下的文件清空，然后把原 kz-admin 的[前端项目](https://github.com/kuizuo/kz-vue-admin)与[后端项目](https://github.com/kuizuo/kz-nest-admin)放到 apps 下。修改下 README.md 与 package.json 其启动命令即可。

![](https://img.kuizuo.cn/image_eYL2rKrakb.png)

## 依赖升级

我原先的nestjs依赖是8.0.0，但是技术发展太快，nestjs
9.0.0都已经发布了，所以这次更新属于大版本更新，通常属于**破坏性更新，可能会导致原代码失效**，所以更新依赖要慎重。

我使用的是[antfu/taze](https://github.com/antfu/taze "antfu/taze") 来更新依赖，也可以使用 `yarn upgrade-interactive -- latest`。

```javascript
npx taze -r
```

由于此次属于大版本更新，所以使用`taze major`，小版本则使用 `taze minor`。

![](https://img.kuizuo.cn/image_xJ_Bh1NZih.png)

`npx taze major -r -w` 将更新依赖写入到package.json下，接着执行pnpm i更新依赖即可。

既然都将nestjs更新了，那么nestjs相关生态的库自然也是要更新的，于是就遇到的typeorm 0.2.0 → 0.3.0用法的问题，主要是将findOne等方法改写，如 `findOne(id) → findOneBy({ id })` 。整个过程还算顺利，

## 使用ApiFox编写接口文档与接口测试

在原项目中我Swagger写的其实够完善，但是在代码协同上只给前端一个Swagger地址不是很友好。但直到我接触并体验一段时间ApiFox后，让我更想去编写Swagger，给前端同事一个良好的Api接口测试体验，因为我自身也作为前端开发者，我太清楚API接口文档的重要性了。

其实早听闻ApiFox，但当时我还在用ApiPost，觉得ApiPost足够好用就没有更换的欲望。直到看到别人给我分享用ApiFox编写的接口文档时，让我眼前一亮，至于有多好用，可以参阅官方的介绍视频[21分钟学会Apifox](https://www.bilibili.com/video/BV1ae4y1y7bf "21分钟学会Apifox")。发自使用者内心的好用，下面会有些实际接口案例来说明到底有多好用。

你可以访问 [https://admin.kuizuo.cn/swagger-ui](https://admin.kuizuo.cn/swagger-ui "https://admin.kuizuo.cn/swagger-ui") 来查看kz-admin的Swagger文档

json格式为[https://admin.kuizuo.cn/swagger-ui/json](https://admin.kuizuo.cn/swagger-ui/json "https://admin.kuizuo.cn/swagger-ui/json")，用于导入ApiFox中。

ApiFox在线链接: [https://www.apifox.cn/apidoc/shared-7a07def2-5b82-4c71-bf57-915514f61f25](https://www.apifox.cn/apidoc/shared-7a07def2-5b82-4c71-bf57-915514f61f25 "https://www.apifox.cn/apidoc/shared-7a07def2-5b82-4c71-bf57-915514f61f25") 访问密码: kz-admin

### 数据实体

本次重构对于数据实体花费的时间比较多，主要就是数据实体重命名，如

- CreateUserDto → UserCreateDto

- UpdateUserDto → UserUpdateDto

- DeleteUserDto → UserDeleteDto

- PageUserDto→ UserPageDto

- ...

将操作动词后置，这样做好处就是不用从一堆`CreatxxxxDto`中找一个`CreateUserDto`，而是转变成从几个`UserxxxxDto`找`UserCreateDto`，就像下图这样，左侧Swagger，右侧ApiFox，在数据实体比较多的时候显示的会更加直观。

![](https://img.kuizuo.cn/image_a4g_9OfyUw.png)

![](https://img.kuizuo.cn/image_avg9_2fE5G.png)

当然在ApiFox中可以通过搜索来筛选模型，但在开发体验方面，我认为此次重命名重构还是非常有必要的。

定义数据实体（Schemas）非常重要，这样我们就能知道该请求接口应该传递什么参数，会接收到什么样的数据。

### 接口文档

Apifox是以文档作为驱动的，可以说把Swagger文档写好，Apifox就会好用。直接上例子

以用户新增和分页查询用户为例，直接上效果图（左侧是ApiFox，右侧为Swagger代码）

![](https://img.kuizuo.cn/image_Zs3cEmA7KD.png)

![](https://img.kuizuo.cn/image_WLjlJRNBlH.png)

在定义完Swagger并通过ApiFox导入后，不用修改ApiFox就能得到上述效果。这里强烈建议将ApiFox接口问题，与nestjs的Swagger代码进行对比，就能体会到写好Swagger就能得到一份如此优雅的Api文档。

做前端和做后端看到这文档，这不得发自内心的赞美。

### 了解更多

此外 ApiFox 的好处远远不止于此，篇幅有限，好东西不是一句两句就能说明白的东西，建议自行体验一番，绝对会有不一样的收获。

## 回顾项目

Vben admin 是我21年6月当时接触 Vue3 的第一个项目，在当时Vue3测试版已经发布，而vue-element-admin都早已烂大街了，也有点审美疲劳了。想给自己换一个后台管理系统的模板，恰好无意间刷到了 Vben Admin，管理面板的效果让我眼前一亮，迄今为止我都认为非常耐看。

但是Vben Admin仅仅只是前端模板与mock数据，并无后端数据，于是就正好利用我使用的 Node 后端框架 Nestjs 来编写后端服务。但当时项目并不完善，在我编写了几个相似的后端管理的项目后，将核心部分抽离出来，并将其封装出来，kz-admin也就此诞生。

鸣谢 [hackycy/sf-nest-admin](https://github.com/hackycy/sf-nest-admin)，我的后端 nestjs 架构与部分代码都借鉴该项目。

最后也要感谢 Vben 项目，在当时让我进一步了解到 Vite + Vue + TypeScript 等最新前端相关技术。
