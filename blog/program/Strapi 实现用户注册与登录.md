---
slug: strapi-user-register-and-login
title: Strapi 实现用户注册与登录
date: 2022-09-03
authors: kuizuo
tags: [strapi, nuxt, next]
keywords: [strapi, nuxt, next]
description: Strapi 实现用户注册与登录
---

在官方博客 [Registration and Login (Authentication) with Vue.js and Strapi](https://strapi.io/blog/registration-and-login-authentication-with-vue-js-and-strapi-1) 中演示如何实现注册与登录。实际重点部分是 Strapi 的[角色和权限插件](https://docs.strapi.io/developer-docs/latest/plugins/users-permissions.html)，可以说这个插件让开发者不用再为项目考虑的用户登录注册与鉴权相关。

此外这里有个在线示例可供体验：[Vitesse Nuxt 3 Strapi](https://vitesse-nuxt3-strapi.vercel.app)

<!-- truncate -->

## 创建 Strapi 项目

这里省略创建 strapi 项目创建过程，具体可到 [Quick Start Guide](https://docs.strapi.io/developer-docs/latest/getting-started/quick-start.html) 中查看。创建完项目，并注册管理员账号后，打开管理面板，根据自己需求创建数据。下面会介绍下管理面板的一些操作（以下针对中文面板）

### 角色列表

打开 **设置 => 用户及权限插件 => 角色列表**

![image-20220825131929320](https://img.kuizuo.cn/image-20220825131929320.png)

默认有两个角色 Authenticated 与 Pubilc，都不可删除，其中还有一个 Admin 是我自己创建的角色，用于分配管理员的权限。

Authenticated 对应的也就是登录后的角色，即携带 **Authorization** 协议头携带 jwt 的用户。

另一个 Pubilc 则是未授权用户，默认权限如下

![image-20220825132235027](https://img.kuizuo.cn/image-20220825132235027.png)

### 权限分配

双击角色可以到权限分配页面，比方说我想给 Authenticated 角色分配 Restaurant 表中查询数据，就可以按照如下选项中勾选，并且勾选其中一个权限（增删改查）可以在右侧看到对应的请求 api 接口（路由）

![image-20220825132716257](https://img.kuizuo.cn/image-20220825132716257.png)

### 默认角色

可以在 **设置 => 用户及权限插件 => 高级设置** 中分配默认角色，此外这里还可以配置注册，重置密码等操作。对于这些功能而言，传统开发就需要编写相当多的代码了，而 Strapi 的 [角色和权限](https://docs.strapi.io/developer-docs/latest/plugins/users-permissions.html) 插件能省去开发这一部分功能的时间。

![image-20220825132948740](https://img.kuizuo.cn/image-20220825132948740.png)

### 管理员权限

在 **设置 => 管理员权限** 也可以看到角色列表与用户列表，不过这个只针对登录 strapi 仪表盘的用户，与实际业务的用户毫不相干。通俗点说就是数据库系统的用户与后台管理系统用户的区别。

一开始登录面板创建的用户在 **设置 => 管理员权限 => 用户列表** 中可以看到，而通过api http://localhost:1337/api/auth/local/register 注册的用户则是在 **内容管理 => User** 中查看。

## 使用 HTTP 请求用户操作（通用）

这里先给出官方提供的注册和登录地址，分别是：

[http://localhost:1337/api/auth/local/register](http://localhost:1337/api/auth/local/register)

[http://localhost:1337/api/auth/local](http://localhost:1337/api/auth/local)

分别可在 [Login](https://docs.strapi.io/developer-docs/latest/plugins/users-permissions.html#login) 与 [Register](https://docs.strapi.io/developer-docs/latest/plugins/users-permissions.html#registration) 中查看官方演示例子，例如

import Tabs from '@theme/Tabs'; 
import TabItem from '@theme/TabItem';

```mdx-code-block
<Tabs>
<TabItem value="login" label="登录" default>
```

```js {4}
import axios from 'axios';

// Request API.
axios.post('http://localhost:1337/api/auth/local', {
    identifier: 'user@strapi.io',
    password: 'strapiPassword',
  })
  .then((response) => {
    // Handle success.
    console.log('Well done!');
    console.log('User profile', response.data.user);
    console.log('User token', response.data.jwt);
  })
  .catch((error) => {
    // Handle error.
    console.log('An error occurred:', error.response);
  });
```

```mdx-code-block
</TabItem>
<TabItem value="register" label="注册">
```

```js {4}
import axios from 'axios';

// Request API.
axios.post('http://localhost:1337/api/auth/local/register', {
    username: 'Strapi user',
    email: 'user@strapi.io',
    password: 'strapiPassword',
  })
  .then((response) => {
    // Handle success.
    console.log('Well done!');
    console.log('User profile', response.data.user);
    console.log('User token', response.data.jwt);
  })
  .catch((error) => {
    // Handle error.
    console.log('An error occurred:', error.response);
  });
```

```mdx-code-block
</TabItem>
</Tabs>
```

除了登录外，还有几个api可能还会用到如获取个人信息，重置密码，修改密码，发送邮箱验证等等。更多可到 [Roles & Permissions](https://docs.strapi.io/developer-docs/latest/plugins/users-permissions.html#authentication) 中查看

通过 HTTP 这种方案可以说是最通用的了，不过有些框架还提供相应的模块来调用 Strapi。

## Nuxt

官方 Nuxt3 提供了 hooks 方案使用 Strapi。具体可看 [Nuxt Strapi Module](https://strapi.nuxtjs.org/)。Nuxt2 可看[这里](https://strapi-v0.nuxtjs.org/hooks)

通过相应的 hooks 就可以实现登录注册以及数据增删改查的功能，演示例子可看 [Usage](https://strapi.nuxtjs.org/usage)

这里有一份我创建的预设模板 [kuizuo/vitesse-nuxt3-strapi](https://github.com/kuizuo/vitesse-nuxt3-strapi)，一开始的示例也是基于这个模板来搭建的。不过目前 Strapi 对 TypeScript 支持不是那么友好，尤其在 window 下会出现无法运行的情况，详看这个 [pr](https://github.com/strapi/strapi/pull/14088)。所以目前 backend 使用 js 创建，然后增加 ts 相关支持的，所以有些 ts 支持可能不是那么友好。

:::note

原本我考虑的是使用 starter 方式来创建nuxt3 strapi项目，但是就在我创建完 starter 与 template 准备使用 `yarn create strapi-starter strapi-nuxt3 https://github.com/kuizuo/strapi-starter-nuxt3` 下载模板时，不出意外又出意外的报错了，由于这个报错也不好排查就暂时放弃了。

总之又是一趟白折腾的经过。

:::


## Next

Next 我暂未找到相关库可以像 Nuxt 提供 Strapi 的服务。不过 Strapi 官方有提供 [sdk](https://github.com/strapi/strapi-sdk-javascript)的方案来调用 strapi 服务，而不用发送 http 请求的形式来调用，具体可以到官方提供的 [sdk](https://github.com/strapi/strapi-sdk-javascript) 查看如何使用，这里不做演示。有如下两个SDK可供选择：

[strapi/strapi-sdk-javascript](https://github.com/strapi/strapi-sdk-javascript) 官网

[Strapi SDK (strapi-sdk-js.netlify.app)](https://strapi-sdk-js.netlify.app/) 社区
