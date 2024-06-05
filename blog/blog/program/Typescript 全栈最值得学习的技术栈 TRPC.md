---
slug: typescript-full-stack-technology-trpc
title: Typescript 全栈最值得学习的技术栈 TRPC
date: 2023-03-07
authors: kuizuo
tags: [trpc, next, prisma, zod, auth.js]
keywords: [trpc, next, prisma, zod, auth.js]
description: 本文介绍了 tRPC 技术以及它与传统 RESTful API 的区别。同时 tRPC 可以帮助人们更快地开发全栈 TypeScript 应用程序，同时无需传统的 API 层，并保证应用程序在快速迭代时的稳定性。
image: https://img.kuizuo.cn/trpc-banner.png
toc_max_heading_level: 3
---

如果你想成为一个 **Typescript 全栈工程师**，那么你可能需要关注一下 [tRPC](https://trpc.io/) 框架。

本文总共会接触到以下主要技术栈。

- [Next.js](https://nextjs.org/ 'Next.js')
- [TRPC](https://trpc.io/ 'TRPC')
- [Prisma](https://www.prisma.io/ 'Prisma')
- [Zod](https://github.com/vriad/zod 'Zod')
- [Auth.js](https://authjs.dev/ 'Auth.js')

不是介绍 tRPC 吗，怎么突然出现这么多技术栈。好吧，主要这些技术栈都与 typescript 相关，并且在 trpc 的示例应用中都或多或少使用到，因此也是有必要了解一下。

在线体验地址：[TRPC demo](https://trpc.kuizuo.cn/)

<!-- truncate -->

## End-to-end typesafe APIs(端到端类型安全)

在介绍相关技术前，不妨思考一个问题。

> 当进行网络请求和 API 调用时，你是否知道本次请求的参数类型以及返回的响应数据类型？知道了请求的数据类型与响应的数据类型，会为得到的 json 数据定义 type/interface，使其有更好的类型提示？还是会在 any 类型下获取属性，但由于没有类型提示，导致写错个单词，最终提示 Cannot read properties of undefined (reading 'xxx')？

对于大部分前端应用而言，类型往往常被忽略的，这就导致不知道这个请求的提交参数、响应结果有什么数据字段。举个 axios 发送 post 请求的例子

![image-20230308142331808](https://img.kuizuo.cn/image-20230308142331808.png)

这是一个 post 请求用于实现登录的，但是这个响应数据 data 没有任何具体提示（这里的提示是 vscode 记录用户最近输入的提示），这时候如果一旦对象属性拼写错误，就会导致某个数据没拿到，从而诱发 bug。同理提交的请求体 body 不做约束，万一这个请求还有验证码 code 参数，但是我没写上，那请求就会失败，这是就需要通过调试输出，甚至需要抓包比对原始数据包，其过程可想而知。

最主要的是没有类型约束的情况下，非常容易出现访问某个对象属性不存在，js 开发者肯定经常遇到如下错误提示。

```typescript
Cannot read properties of undefined (reading 'xxx')
```

有太多时候就是因为没有类型，无形间诱发 bug，这也是很多做 api 接口都常常忽视的一点。

> 因此我个人所认为的未来 Web 框架形态是要满足的前提就是前后端类型统一，即可以将后端的类型无缝的给前端使用，反之同理。而像 Next、Nuxt 这样的全栈框架便是趋势所向。

当然 axios 是可以通过泛型的方式拿到 data 的数据类型提示，就如下图所示。

![image-20230308142452678](https://img.kuizuo.cn/image-20230308142452678.png)

但这样为了更好的类型提示，无形之间又增加了工作量，我需要定义每个接口的 Response 与 Body 类型，就极易造成开发疲惫，不愿维护代码。而本次所要介绍的技术栈 tRPC 就能够帮你省去重复的类型定义的一个 web 全栈框架。

## [tRPC](https://github.com/trpc/trpc)

tRPC 是一个基于 TypeScript 的远程过程调用框架，旨在简化客户端与服务端之间的通信过程，并提供高效的类型安全。它允许您使用类似本地函数调用的方式来调用远程函数，同时自动处理序列化和反序列化、错误处理和通信协议等底层细节。

借官方 Feature

- Automatic type-safety（自动类型安全）
- Snappy DX（敏捷高效的开发者体验）
- Is framework agnostic （不依赖于特定框架）
- Amazing autocompletion（出色的自动补全功能）
- Light bundle size（轻量级打包大小）

### 什么时候该使用 tRPC

这个问题非常好，因为我在了解到 tRPC，并参阅了一些基本示例与实践一段时间后发现 trpc 和 http 的应用场景可以说非常相似，完全可以使用 trpc 来替代 http，只不过写法上从 **发送 http 请求 ⇒ 调用本地函数**（这在后面会演示到）。

而 trpc 又以类型安全与高效著称，如果你的 Web 应用的程序是基于 typescript，并且需要有高效的性能，那么 tRPC 就是一个很好的选择。

tRPC 可以作为 REST/GraphQL 的替代品，如果前端与后端共享代码的 TypeScript monorepo，trpc 则可以无需任何类型转换，也不太会有心智负担。

**请记住，tRPC 只有当您在诸如 Next、Nuxt、SvelteKit、SolidStart 等全栈项目中使用 TypeScript 时，tRPC 才会发挥其优势。**

## tRPC 如何进行接口调用

<video src="https://assets.trpc.io/www/v10/v10-dark-landscape.mp4" controls="controls" width="100%" height="auto"></video>

一图胜千言，你可以点击 [这里](https://trpc.io/#try-it-out '这里') 在线体验一下 tRPC，并且查看其目录结构，以及调用方式。下面我一步步讲解如何进行接口调用。

### 定义服务端

这里以 Next.js 的目录结构而定。创建 `server/trpc.ts`，如下代码。分别导出 router, middleware, procedure

```typescript title='server/trpc.ts' icon='logos:nextjs-icon'
import { initTRPC } from '@trpc/server'

const t = initTRPC.create()

export const router = t.router
export const middleware = t.middleware
export const publicProcedure = t.procedure
```

创建项目(根)路由文件 `pages/api/trpc/[trpc].ts`

```typescript title='server/trpc.ts' icon='logos:nextjs-icon'
import * as trpc from '@trpc/server'
import { publicProcedure, router } from './trpc'

const appRouter = router({
  greeting: publicProcedure.query(() => 'hello tRPC!'),
})

export type AppRouter = typeof appRouter
```

此时已经定义好了一个路由地址 `api/trpc/[trpc].ts`（这里 endpoint(端点)会在客户端中使用到），以及 `greeting` 函数，服务端的工作就暂且完毕。

### 创建客户端

创建 `utils/trpc.ts` 文件，代码如下

```typescript title='utils/trpc.ts' icon='logos:nextjs-icon'
import { httpBatchLink } from '@trpc/client'
import { createTRPCNext } from '@trpc/next'
import type { AppRouter } from '../pages/api/trpc/[trpc]'

function getBaseUrl() {
  if (typeof window !== 'undefined') {
    // In the browser, we return a relative URL
    return ''
  }
  // When rendering on the server, we return an absolute URL

  // reference for vercel.com
  if (process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL}`
  }

  // assume localhost
  return `http://localhost:${process.env.PORT ?? 3000}`
}

export const trpc = createTRPCNext<AppRouter>({
  config() {
    return {
      links: [
        httpBatchLink({
          url: getBaseUrl() + '/api/trpc',
        }),
      ],
    }
  },
})
```

在 `_app.tsx` 包装一下

```typescript title='_app.tsx' icon='logos:nextjs-icon'
import type { AppType } from 'next/app'
import { trpc } from '../utils/trpc'

const MyApp: AppType = ({ Component, pageProps }) => {
  return <Component {...pageProps} />
}

export default trpc.withTRPC(MyApp)
```

有了这个对象后，我们就可以开始尽情调用服务端所定义好了函数了。

当你导入 trpc 并输入 `trpc.` 时，将会提示出服务端定义好的 `greeting` 函数，如下图所示。

![](https://img.kuizuo.cn/image_YDKc7TixQA.png)

此时通过 `const result = trpc.greeting.useQuery()` 便可调用 `greeting` 函数，其中 `result.data` 便可拿到 `'hello tRPC!'` 信息。

### 这个过程发生了什么？

> 文档: [useQuery() | tRPC](https://trpc.io/docs/useQuery 'useQuery() | tRPC')

不妨此时打开控制台面板，看看请求

![](https://img.kuizuo.cn/image_WfW8ehqUKz.png)

![](https://img.kuizuo.cn/image_qicvoGjshx.png)

不难看出，调用 greeting 函数本质是向 `/api/trpc/greeting` 发送了 http 请求，并且携带参数 batch 和 input，虽然我们暂时还没有传。默认 input 为 {}。

要支持传递参数，首先需要在服务端定义传递参数的类型（会有 Zod 对参数效验），这样客户端才有对应的类型提示。然后调用 greeting 函数时，通过通过函数参数的形式来传递请求参数。

举例说明，比如说我们将 appRouter 改写成这样，通过 input 参数指定了 `useQuery` 需要传递一个 `name` 为字符串且不为空的对象。

```typescript
import z from 'zod'

const appRouter = router({
  greeting: publicProcedure
    .input(
      z.object({
        name: z.string().nullish(),
      }),
    )
    .query(({ input }) => {
      return {
        text: `hello ${input?.name ?? 'world'}`,
      }
    }),
})
```

调用 `trpc.greeting.useQuery({ name: 'kuizuo' })` 发送的请求的 query 参数则变为

![](https://img.kuizuo.cn/20230307214659.png)

不仅于此，你如果同时调用了多次 greeting 函数，如

```typescript title='pages/index.tsx'
const result1 = trpc.greeting.useQuery({ name: 'kuizuo1' })
const result2 = trpc.greeting.useQuery({ name: 'kuizuo2' })
const result3 = trpc.greeting.useQuery({ name: 'kuizuo3' })
```

tRPC 会将这三次函数调用合并成一次 http 请求，并且得到的响应本文也是以多条数据的形式返回

![](https://img.kuizuo.cn/image_ufrhaugaIj.png)

![](https://img.kuizuo.cn/image_cvlDJjhwPl.png)

分别输出三者 result 也没有任何问题。

![](https://img.kuizuo.cn/image_hbL8So_RzB.png)

这是 tRPC 的一个特性：**请求批处理，将同时发出的请求（调用）可以自动组合成一个请求。**

#### [useMutation() | tRPC](https://trpc.io/docs/useMutation 'useMutation() | tRPC')

tRPC 同样也支持 post 请求，例如

服务端代码

```typescript title='server/trpc.ts' icon='logos:nextjs-icon'
const appRouter = router({
  createUser: publicProcedure.input(z.object({ name: z.string() })).mutation(req => {
    const user: User = {
      name: req.input.name,
    }

    return user
  }),
})
```

客户端代码

```typescript title='pages/index.tsx' icon='logos:nextjs-icon'
export default function IndexPage() {
  const mutation = trpc.createUser.useMutation()

  // ERROR!
  // mutation.mutate({ name: 'kuizuo' });

  const handleCreate = () => {
    mutation.mutate({ name: 'kuizuo' })
  }

  return (
    <div>
      <button onClick={handleCreate} disabled={mutation.isLoading}>
        Create
      </button>
      {mutation.error && <p>Something went wrong! {mutation.error.message}</p>}
    </div>
  )
}
```

:::danger

这里需要注意 `mutate` 方法无法在外层直接调用，否则将会提示

```typescript
Unhandled Runtime Error
Error: Maximum update depth exceeded. This can happen when a component repeatedly calls setState inside componentWillUpdate or componentDidUpdate. React limits the number of nested updates to prevent infinite loops.
```

主要防止这个组件被其他组件调用，此时自动调用 mutate 函数，导致不可控且循环调用的情况，因此需要通过一个事件（比如点击事件）来触发。

:::

此时请求变为 post 请求，并且携带的参数也以 body 形式传递。

![](https://img.kuizuo.cn/image_-qEI8jR1uM.png)

![](https://img.kuizuo.cn/image_RTdWJn_55p.png)

通过 useQuery 和 useMutation 就能够用 tRPC 实现最基本的 CRUD。此外还有 useInfiniteQuery 可以用作类似无限下拉查询，类似 [SWR 无限加载](https://swr.bootcss.com/examples/infinite-loading)。useQueries 批量查询，使用 [Subscriptions](https://trpc.io/docs/subscriptions) 进行订阅 WebSocket 等等。

tRPC 针对 react 项目的查询主要依赖于 [@tanstack/react-query](https://tanstack.com/query/v4/docs/react/adapters/react-query '@tanstack/react-query')，你也可以到 [tRPC React Query documentation](https://trpc.io/docs/react-query 'tRPC React Query documentation') 查看相关 hook。

从上述例子中你就会发现，tRPC 将 http 请求给我们包装成了函数形式调用，即上文所说的，调用服务端接口的形式由 **发送 http 请求 ⇒ 调用本地函数**。

### 不足

不过也并非没有缺点（个人认为）。

首先不如传统的 RESTFUL 来的直观，假设我现在在服务端定义了一个服务，那么我只能通过`@trpc/client` 创建客户端进行调用。虽然也能用 http 的形式，但调用的很不优雅。

在我印象中，RPC 框架通常是可以跨语言进行调用的，比如 gRPC 框架，然而**tRPC 目前只能在 Typescript 项目中进行调用**，我倒是希望能向 gRPC 那个方向发展，不过不同语言间的类型安全又是个大麻烦。

学习成本与项目成本偏高，tRPC 对整个全栈项目的技术要求比较高，并且限定于 typescript，如果你~~想~~将你的项目从传统的 Restful 迁移到 tRPC 上，无疑是个工程量大，且不讨好的事。

## 创建工程

这里选用 [Create T3 App](https://create.t3.gg/ 'Create T3 App') 用于创建应用（也可以选择 [trpc/examples-next-prisma-starter](https://github.com/trpc/examples-next-prisma-starter 'trpc/examples-next-prisma-starter')），Create T3 App 集成了诸多有关 TypeScript full-stack 相关的技术栈，其中就包括了本文所要介绍的几个技术栈。

![](https://img.kuizuo.cn/image_8BUcBPK8In.png)

```bash
pnpm create t3-app@latest
```

安装过程如下

![](https://img.kuizuo.cn/image_ERGzEt2Tq8.png)

### prisma

此时安装完先别急着 pnpm run dev 启动项目，首先执行

```bash
npx prisma db push
```

运行结果如下

```bash
Environment variables loaded from .env
Prisma schema loaded from prisma schema.prisma
Datasource "db": SQLite database "db.sqlite" at "file:./db.sqlite"

SQLite database db.sqlite created at file:./db.sqlite

Your database is now in sync with your Prisma schema. Done in 81ms
```

这会将数据库与 prisma 的 schema 同步，说人话就是将数据库的表与 `schema.prisma` 文件中的 model 对应。

<details>

<summary>schema.prisma</summary>

```prisma title='prisma/schema.prisma'
generator client {
    provider = "prisma-client-js"
}

datasource db {
    provider = "sqlite"
    url      = env("DATABASE_URL")
}

model Example {
    id        String   @id @default(cuid())
    createdAt DateTime @default(now())
    updatedAt DateTime @updatedAt
}

// Necessary for Next auth
model Account {
    id                String  @id @default(cuid())
    userId            String
    type              String
    provider          String
    providerAccountId String
    refresh_token     String? // @db.Text
    access_token      String? // @db.Text
    expires_at        Int?
    token_type        String?
    scope             String?
    id_token          String? // @db.Text
    session_state     String?
    user              User    @relation(fields: [userId], references: [id], onDelete: Cascade)

    @@unique([provider, providerAccountId])
}

model Session {
    id           String   @id @default(cuid())
    sessionToken String   @unique
    userId       String
    expires      DateTime
    user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)
}

model User {
    id            String    @id @default(cuid())
    name          String?
    email         String?   @unique
    emailVerified DateTime?
    image         String?
    accounts      Account[]
    sessions      Session[]
}

model VerificationToken {
    identifier String
    token      String   @unique
    expires    DateTime

    @@unique([identifier, token])
}

```

</details>

create-t3-app 默认使用的 sqlite 数据库，优点就是你无需安装任何数据库的环境，将会在 prisma 目录下创建 `db.sqlite` 文件来存放数据。但是缺点很明显，性能与部署方面是远不如主流服务级别的数据库。尤其是部署，这在后面会说。

将会创建 `Account` `Example` `Session` `User` `Verification Token` 表，这里需要教你一个命令

```bash
npx prisma studio
```

此时访问 localhost:5555 将会得到一个 prisma 面板，即项目的所有 model 。

![](https://img.kuizuo.cn/image_QBXnHdoewh.png)

关于 prisma 更多命令请参考 [Prisma CLI Command Reference](https://www.prisma.io/docs/reference/api-reference/command-reference 'Prisma CLI Command Reference')

prisma 在线体验：[Prisma Playground | Learn the Prisma ORM in your browser](https://playground.prisma.io/)

由于 create-t3-app 已经封装好了[数据库的操作](https://create.t3.gg/en/usage/prisma)，并且导出 prisma 对象，所以你只需要配置好环境变量便可。

主要代码如下

```typescript title='server/db.ts'
import { PrismaClient } from '@prisma/client'

export const prisma = new PrismaClient()
```

#### 类型提示

在上面所定义的 model，都会被 prisma client 创建对应的 typescript 类型（在`node_modules/.prisma/index.d.ts`），你就可以直接通过 prisma.modelName 来操作 model，例如 Example（这里就不做注释了）

```typescript
import { prisma } from '~/server/db'

prisma.post.findUnique({ where: { id: 1 } })

prisma.post.create({ data: {} })

prisma.post.update(id, { data: {} })

prisma.post.delete(id)

prisma.post.count()
```

#### 数据迁移

我之前如果做数据库备份的话，我通常会在数据库管理软件（Navicat）将整个数据库转储为 SQL 文件，然后要用的时候在运行该 SQL 文件。而这样做呢虽然方便，但是数据都比较死，而且版本多了 sql 文件也多，导入繁琐。

此时就可以使用 [Migrate](https://www.prisma.io/docs/getting-started/setup-prisma/start-from-scratch/relational-databases/using-prisma-migrate-typescript-postgres)，通过命令的方式自动为我们生成当前版本下的 sql 文件，而需要用到的也通过命令的形式运行 sql 文件。

#### 数据生成

你可以编写一个 [seed 脚本](https://www.prisma.io/docs/guides/database/seed-database#example-seed-scripts)，用于插种（生成）自定义数据。

---

prisma 不是本文重点，篇幅略少，但是作为 Typeorm 的长期使用者而言，我认为 prisma 会比 typeorm 友善一些，至少从文档上来说 prisma 大胜一筹，而且很多 node 的 web 框架都优先 prisma 作为 orm 框架（除了 nest.js），但不过这两个仓库的 issues 数量有点惨不忍睹。。。

### next-auth

我想先简单介绍一下 next-auth（背后由[Auth.js](https://authjs.dev/ 'Auth.js') 提供）。

从名字来看也不难猜出，这是一个 next.js 的 auth 库。该库提供了多种身份验证策略，如基于密码的身份验证，OAuth 等等。并且你只需要简单的几行代码，提供好相关信息便可启用身份验证和授权功能。

你可以到这个网站 [NextAuth.js Example](https://next-auth-example.vercel.app/ 'NextAuth.js Example')体验一番。下面是一些代码演示

由于 create-t3-app 默认是 Discord OAuth，因此我这边替换成使用者更多的 Github。（至于如何创建 Github OAuth Apps，在我之前的文章以及外面诸多文章中都有介绍到，这里不在演示了，附上配置图）

![](https://img.kuizuo.cn/image__B1RYeiFze.png)

首先在

server/auth.ts 中 导入

```typescript title='server/auth.ts' icon='logos:nextjs-icon'
import CredentialsProvider from 'next-auth/providers/credentials'
import GithubProvider from 'next-auth/providers/github'
```

并在 options 中设置好 providers，如下

```typescript title='server/auth.ts' icon='logos:nextjs-icon'
export const authOptions: NextAuthOptions = {
  callbacks: {
    session({ session, user }) {
      if (session.user) {
        session.user.id = user.id
        // session.user.role = user.role; <-- put other properties on the session here
      }
      return session
    },
  },
  adapter: PrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        username: { label: 'Username', type: 'text', placeholder: 'kuizuo' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials, req) {
        // Add logic here to look up the user from the credentials supplied
        const user = { id: '1', name: 'kuizuo', email: 'hi@kuizuo.cn' }

        if (user) {
          return user
        } else {
          return null
        }
      },
    }),
    GithubProvider({
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
    }),
  ],
}
```

不过此时会提示 env 对象没有 GITHUB_CLIENT_ID 属性，需要在 env.mjs 定义好 GITHUB_CLIENT_ID 与 GITHUB_CLIENT_SECRET。类型安全嘛，你可不想 GITHUB 不小心输成 ~~GAYHUB~~ 导致找不到这个值把。

当上述在设置完毕后，点击 Sign in 按钮便可跳转到 next-auth 所提供的简单登录表单。

![](https://img.kuizuo.cn/image_9eowvvnwU2.png)

如果你想自定义修改登录页面，可以参考该视频[Create your own next-auth Login Pages - YouTube](https://www.youtube.com/watch?v=kB6YNYZ63fw 'Create your own next-auth Login Pages - YouTube')

## 部署 tRPC

通常来说 tRPC 会配合全栈框架使用，因此可以非常轻松的部署在 Vercel，Netlify 上。如今 Vercel 应该也已经家喻户晓了，因此这里就不演示如何部署，可到 [Vercel • Create T3 App](https://create.t3.gg/en/deployment/vercel 'Vercel • Create T3 App') 中查看相关步骤。

:::warning

不过要注意，Vercel 并不提供文件读写操作，即无法实现数据存储，因此你如果需要提供数据读取的操作，那么普通需要一个远程的数据库服务，将 DATABASE_URL 环境变量替换成线上地址。如

```title='env'
DATABASE_URL=postgresql://myuser:mypassword@localhost:5432/mydb
```

这里推荐 [railway](https://railway.app/ 'railway') 与 [supabase](https://supabase.com/ 'supabase') 都提供远程数据服务，且有免费额度。（不过我比较好奇为啥好多远程数据服务多数都是 postgresql）

如果你执意要使用 vercel 部署，当你触发数据库服务时便会报错，以下是相关截图。

![](https://img.kuizuo.cn/image_7_XKmbuK87.png)

:::

至于说自行部署的话，create t3 app 提供了 docker 相关镜像，你可以直接使用 docker 部署，具体步骤可参考 [Docker • Create T3 App](https://create.t3.gg/en/deployment/docker)。

## 示例

这里我提供了一个简单的示例，你可以 [点我](https://trpc.kuizuo.cn) 访问体验一下（项目部署在 Vercel，而数据库服务在腾讯云，登录服务又依赖 Github，所以项目会稍微有那么慢）。整个项目结构大致如下

![](https://img.kuizuo.cn/image_z_YaR-RnSu.png)

你可以在 [Example Apps | tRPC](https://trpc.io/docs/example-apps 'Example Apps | tRPC') 查看 trpc 的示例应用。

## 结语

如果你是用 Next，Nuxt 等这样的全栈框架，并且你的后端服务使用 Typescript 编写，不妨试试 trpc，你会惊喜地发现，它颠覆了传统的 API 交互，使你的 typescript 全栈应用程序的开发变得更加高效和流畅。

从 JavaScript 到 TypeScript 的演变，全栈应用的端到端类型安全，TypeScript 目前正在逐渐成为前端开发中不可或缺的一部分，也许未来的某一天当人们说起前端三件套时，不再是 HTML，CSS，JavaScript，而是 HTML，CSS，TypeScript。

再说到我为何会去尝试 tRPC，有很大的原因是因为厌倦了传统后端开发，厌倦了 nest.js 开发。然而现实生活中，你所厌倦的，往往是能为你提供收入的。人们总是做着自己不愿做的事，但生活所迫，谁又愿意呢。
