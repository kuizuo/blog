---
slug: use-supabase-as-backend-service
title: 将 Supabase 作为下一个后端服务
date: 2023-02-18
authors: kuizuo
tags: [supabase, nuxt, project]
keywords: [supabase, nuxt, project]
description: 本文介绍了如何使用 Supabase 作为后端服务，使开发人员可以更快地构建和部署应用程序，无需配置数据库或编写复杂的身份验证代码。将使用 Nuxt.js 和 Supabase，以实现一个图床网站为例，来演示如何在前端中使用 Supabase API 和 Storage 服务。
image: https://img.kuizuo.cn/213727234-cda046d6-28c6-491a-b284-b86c5cede25d.png
toc_max_heading_level: 3
---

对于想快速实现一个产品而言，如果使用传统开发，又要兼顾前端开发，同时又要花费时间构建后端服务。然而有这么一个平台（Baas Backend as a service）后端即服务，能够让开发人员可以专注于前端开发，而无需花费大量时间和精力来构建和维护后端基础设施。

对于只会前端的人来说，这是一个非常好的选择。后端即服务的平台使得开发人员能够快速构建应用程序，更快地将其推向市场。当然了，你可以将你的后端应用接入 Baas，这样你就无需配置数据库，编写复杂的身份效验。

如果你想了解 Baas，我想这篇文章或许对你有所帮助。

<!-- truncate -->

## 什么是 [Supabase](https://supabase.com/ 'Supabase')?

在摘要部分也介绍到名词 BaaS (Backend as a Service) ，意思为**后端即服务**。这个概念是在我接触 Serverless 的时候了解到的，更准确来说是腾讯云开发。当时在编写小程序的时候，只需要专注与应用业务逻辑，而不用编写数据存储，身份验证，文件存储等后端服务，这些统统由 BaaS 平台所提供。 通常会配合 Serverless 函数使用，通常也叫 FaaS（Function as a Service）。通常来说，FaaS 会依赖于 BaaS 平台。

而 Supabase 便是 BaaS 的平台之一。Supabase 是一个开源的 Firebase 替代品。使用 Postgres 数据库、身份验证、即时 API、边缘函数、实时订阅和存储启动项目。

你也许听过 Firebase，由 Google 提供的私有云服务，但开发者无法修改和扩展其底层代码。而 Supabase 是开源的，提供了类似 Firebase 的功能，且定价灵活，并且官方自称为 [Firebase](https://link.juejin.cn/?target=https://firebase.google.com/ 'Firebase')的替代品。

## BaaS 与 CMS 有何不同？

BaaS 通常只专注于应用的后端服务，而 CMS 则是专注与内容管理。不过 BaaS 比较依赖云服务，而 CMS 通常只依赖于 web 后端技术。如果你想搭建一个内容站点（视频，音频，文章），并且作为网站管理员，那么 CMS 就是一个很好的选择，并且有相当多的主题模板。反之，不想搭建后端服务，减少运营程序，那么毫不犹豫的选择 BaaS。

## 注册 Supabase

进入 [supabase 登录界面](https://app.supabase.com/sign-in) 选择 Continue With Github

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_2yiQ9NHv21.png)

输入 Github 账号密码进入[主页面](https://app.supabase.com/projects '主页面')，新建一个项目

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_0eoOyP8DM2.png)

为该项目起名，设置数据库密码，以及分配地区。

:::warning

创建 supabase 项目对密码要求非常严格，像 a123456 这种根本无法通过，像 ●●●●●●●●●● 密码就可以。

地区方面优先就近原则，而最近的也就是日本与韩国，很无奈 supabase 在大陆和港澳台并未设立服务器。

:::

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_N5CQnx8cnU.png)

等待片刻，你将拥有一个免费的后端服务！

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_Z33n9aUOC7.png)

supabase 会提供一个二级域名供开发者访问，也就是这里 Project Configuration 的 URL，对应的这个二级域名 azlbliyjwcxxxxx 也就是你这个项目的唯一标识 Reference ID（下文称 项目 id）。你可以到 [https://app.supabase.com/project/你的项目 id/settings/api](https://app.supabase.com/project/azlbliyjwcemojkwazto/settings/api 'https://app.supabase.com/project/你的项目id/settings/api') 中查看相关配置。

## 体验一下

这里参考到了官方文档 [Serverless APIs](https://supabase.com/docs/guides/database/api 'Serverless APIs')。

首先，创建一个 todos 表，并新增字段（列）task 为 varchar 类型，Save 保存。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_Do9LHoUsYo.png)

Insert row 添加一行记录，id 为 1，task 为 code。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_R9PEyH-spd.png)

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_MLm6_i1Pb-.png)

现在有了数据后，正常来说我们应该做什么？请求一下数据看看？不不不，应该是设置数据的权限。

打开到下图界面，我们要为 todos 数据新增一个 policy 策略。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_MEKk1-qQFl.png)

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_W-C-pGNh1o.png)

supabase 针对不同的场景提供了相应的策略方案模板，你也可以根据你的需求进行设置，这里作为演示不考虑太复杂，选择第一个允许任何人都可以请求到 todos 数据。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_Oa_424N4gz.png)

接着下一步即可

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_wV_MqXQXcK.png)

此时就新增了一个所有用户都可查询的 todo 的策略，同样的你还可以添加只有授权用户才能够创建更新删除 todo，更新与删除只能操作属于自己的 todo 资源。

这时候设置好了数据的权限后，就可以尝试去请求了，打开下图页面，将 URL 与 apikey 复制下来。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_GDEeyFCI2E.png)

选择你一个 http 请求工具，这里我选用 [hoppscotch](https://hoppscotch.io/ 'hoppscotch')，将信息填写上去，请求将会得到一开始所创建的 todo 数据。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_aSbRfmlwb9.png)

除了 restful api 风格，还支持 graphql 风格，可查阅文档 [Using the API](https://supabase.com/docs/guides/database/api#using-the-api 'Using the API')

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_R0HtkYmznS.png)

### 使用类库

正常情况肯定不会像上面那样去使用，而是通过代码的方式进行登录，CRUD。这里使用 [Javascript Client Library](https://supabase.com/docs/reference/javascript/installing 'Javascript Client Library')，替我们封装好了 supabase 的功能。

首先，安装依赖

```bash
npm install @supabase/supabase-js
```

创建 客户端实例

```typescript
import { createClient } from '@supabase/supabase-js'
```

此时准备好上述的 URL 与 apikey，用于创建 supabase 实例，不过 supabase 还提供 [type 类型支持](https://supabase.com/docs/reference/javascript/typescript-support)，可以将生成的 `database.types.ts` 导入到实例中，如

```typescript
import { createClient } from '@supabase/supabase-js'
import { Database } from 'lib/database.types'

const supabase = createClient<Database>(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY)
```

此时有了 supabse 对象后，就能够请求数据了，像上述通过 http 的方式获取 todos 数据，在这里对应的代码为

```typescript
const { data, error } = await supabase.from('todos').select()
```

[官方的演示例子](https://supabase.com/docs/reference/javascript/select) 非常清晰，这里就不在演示新增更新等示例。

![image-20230218182910913](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image-20230218182910913.png)

## [Supabase 主要功能](https://supabase.com/docs)

### Database 数据库

supabase 基于 PostgreSQL 数据库，因此当你创建完项目后，就自动为你分配好了一个可访问的 PostgreSQL 数据库，你完全可以将其当做一个远程的 PostgreSQL 数据主机。

可以在如下页面中查看到有关数据库连接的信息，当然你看不到密码。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_6uCHh3qrlE.png)

测试连接，结果如下，并无问题

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_8-JOTiLI0G.png)

### Authentication 身份验证

[Auth | Supabase Docs](https://supabase.com/docs/guides/auth/overview 'Auth | Supabase Docs')

supabase 令我感兴趣的是 [Row Level Security](https://supabase.com/docs/learn/auth-deep-dive/auth-row-level-security 'Row Level Security')，supabase 使用 Postgres 的 Row-Level-Security（行级安全）策略，可以限制不同用户对同一张表的不同数据行的访问权限。这种安全机制可以确保只有授权用户才能访问其所需要的数据行，保护敏感数据免受未授权的访问和操作。

在传统的访问控制模型中，用户通常只有对整个表的访问权限，无法限制他们对表中特定数据行的访问。而行级安全技术则通过将访问权限授予到特定的数据行，从而让不同的用户只能访问他们被授权的行。这种行级安全有一个很经典应用场景-多租户系统：允许不同的客户在同一张表中存储数据，但每个客户只能访问其自己的数据行。

这对于传统后端开发而言，如果不借用一些安全框架，实现起来十分棘手，要么业务代码与安全代码逻辑混杂不堪。

权限细分方面，无需担心，supabase 已经为你做好了准备，就等你来进行开发。

#### 第三方登录

对于想要提供第三方登录，supabse 集成多数平台（除了国内），只需要提供 Clinet ID, Client Secret, Redirect URL 便可完成第三方登录。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_OvBRJ_elZR.png)

这里演示下如何使用 Github，首先到打开[New OAuth Application (github.com)](https://github.com/settings/applications/new 'New OAuth Application (github.com)') 创建一个 Oauth Apps，其中 Authorization callback URL 由 supabase 提供，如下图。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_QVspy-oxQK.png)

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_jyaUMSDed2.png)

当你创建完后，会提供 Client ID，与 Client secret，将这两个值填写到 supabase 中，并启用。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_QpRRxpR5o5.png)

此时打开如下页面，将 Site URL 替换成开发环境，或是线上环境，在 Github 登录后将会跳转到这个地址上

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_zmfXC85ayC.png)

此时 supabase 支持 github 登录就已经配置完毕，当你在前端触发登录按钮后，借助[supabase 的 js 库](https://supabase.com/docs/reference/javascript/auth-signinwithoauth 'supabase 的js库')，如

```typescript
const { data, error } = await supabase.auth.signInWithOAuth({
  provider: 'github',
})
```

便可完成 Github 第三方登录。

### Bucket 存储桶

接触过对象存储的开发者对 Bucket 应该不陌生，相当于给你一个云盘，这里演示如何使用。

打开如下界面，这里选择公开存储桶，比如说用于图床。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_2Is4Bfwf8f.png)

点击右上角的 upload files，选择你要上传的图片。你可以为此生成一个访问 URL

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_vkuzeZZVJ_.png)

你可以访问 [1.png](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/publilc/1.png) 来查看这张图片。如果是公开的话 一般都是类似https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/new-bucket/1.png

而私有的为 https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/sign/new-bucket/1.png?token=eyJhbGciOiJIUzI1NiIsInR5cCIxxxxxxxxxxxxxxxxx 路径稍微变化了下，还有就是多了个 token，如果不携带 token 则访问不了图片。

你可以到[Supabase Storage API](https://supabase.github.io/storage-api/ 'Supabase Storage API') 查看 storage 相关 api。

:::tip 现学现用

本文中的所有图片数据都来源于 supabase bucket。

:::

### Edge Functions 边缘函数

边缘函数可以分布在全球的接近您的用户各个地方，类似与 CDN，但 CDN 主要服务于静态资源，而 Edge Functions 可以将你的后端应用接口，像 CDN 那样部署到全球各地。

有兴趣可自行了解。

## **使用 Supabase 编写一个简易图床**

如果只单纯看看 supabase 文档，不去动手实践接入一下，总觉得还是差点意思。于是我准备使用 Nuxt 作为前端框架接入 supabase，官方模块 [Nuxt Supabase](https://supabase.nuxtjs.org/ 'Nuxt Supabase') 去编写一个应用。

原本我是打算写个 Todo List 的（恼，怎么又是 Todo List），但是看到 [官方示例](https://supabase.com/docs/guides/resources/examples#official-examples '官方示例')（一堆 Todo List）后我瞬间就没了兴致 🥀。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_1polvJf0q0.png)

思来想去，不妨就简单做个图床吧。项目地址：[https://image.kuizuo.cn](https://image.kuizuo.cn) 有兴趣可自行阅读[源码](https://github.com/kuizuo/image-hosting)。（**写的相对匆忙，仅作为演示，随时有可能删除，请勿将此站作为永久图床！**）

## 一些你可能比较好奇的问题

### 资源

可以到 https://app.supabase.com/project/项目id/settings/billing/usage 中查看相关资源使用情况，这里我就将截图放出来了。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_Bllhp6XlFz.png)

说实话，对于个人独立开发者的项目都绰绰有余了。

### 费用

在 [资费标准](https://supabase.com/pricing '资费标准') 中可以看到，免费版**最多 2 个项目**，不过在上述的资源，其实已经非常香了，毕竟只需要一个 GIthub 账号就能免费使用，还要啥自行车。

![](https://azlbliyjwcemojkwazto.supabase.co/storage/v1/object/public/public/image_MNtdzsdJ2t.png)

### 网速

国内因为没有 supabase 的服务器节点，然后且有防火墙的存在，所以请求速度偏慢。不过体验下来至少不用梯子，速度慢点但也还在可接受范围。

### 域名

用过 vercel 的你应该会想是不是也能自定义域名呢? 当然，不过这是 supabase pro 版才支持，一个月$25(美刀)，算了算了，再一眼 azlbliyjwcxxxxx.supabase.co~~就会爆炸~~感觉也蛮好记的。

## 结语

说句实话，真心感觉 supabase 不错，尤其是对个人/独立开发者而言，没必要自行去购买服务器，去搭建后端服务，很多时候我们只想专注于应用程序的开发和功能实现，而不是花费大量时间和精力在服务器和后端服务的部署和管理上。
