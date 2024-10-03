---
slug: nextjs-with-hono
title: Next.js 使用 Hono 接管 API
date: 2024-10-02
authors: kuizuo
tags: [nextjs, honojs]
keywords: [nextjs, honojs]
description: 这篇文章详细介绍了如何在 Next.js 项目中使用 Hono 框架来接管 API 路由，以解决 Next.js 自带 API Routes 功能的限制。并探讨了集成步骤、数据验证、错误处理、RPC功能等方面，并提供了实用的代码示例和优化建议。
image: https://img.kuizuo.cn/2024/1002213046-nextjs-with-hono.png
---

直入正题，Next.js 自带的 API Routes (现已改名为 [**Route Handlers**](https://nextjs.org/docs/app/building-your-application/routing/route-handlers)) 异常难用，例如当你需要编写一个 RESTful API 时，尤为痛苦

<!-- truncate -->

![image.png](https://img.kuizuo.cn/2024%2F0930171329-image.png)

这还没完，当你需要数据验证、错误处理、中间件等等功能，又得花费不小的功夫，所以 Next.js 的 API Route 更多是为你的全栈项目编写一些简易的 API 供外部服务，这也可能是为什么 Next.js 宁可设计 [Server Action](https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations) 也不愿为 API Route 提供传统后端的能力。

但不乏有人会想直接使用 Next.js 来编写这些复杂服务，恰好 [Hono.js](https://hono.dev/docs/getting-started/vercel) 便提供相关能力。

这篇文章就带你在 Next.js 项目中要如何接入 Hono，以及开发可能遇到的一些坑点并如何优化。

## Next.js 中使用 Hono

可以按照 [官方的 cli](https://hono.dev/docs/getting-started/vercel#_1-setup) 搭建或者照 next.js 模版 https://github.com/vercel/hono-nextjs 搭建，核心代码 `app/api/[[...route]]/route.ts` 的写法如下所示。

```jsx
import { Hono } from 'hono'
import { handle } from 'hono/vercel'

const app = new Hono().basePath('/api')

app.get('/hello', (c) => {
  return c.json({
    message: 'Hello Next.js!',
  })
})

export const GET = handle(app)
export const POST = handle(app)
export const PUT = handle(app)
export const DELETE = handle(app)
```

从 `hono/vercel` 导入的 `handle` 函数会将 app 实例下的所有请求方法导出，例如 GET、POST、PUT、DELETE 等。

一开始的 User CRUD 例子，则可以将其**归属到一个文件内**下，这里我不建议将后端业务代码放在 app/api 下，因为 Next.js 会自动扫描 app 下的文件夹，这可能会导致不必要的热更新，并且也不易于服务相关代码的拆分。而是在根目录下创建名为 server 的目录，并将有关后端服务的工具库(如 db、redis、zod)放置该目录下以便调用。

![image.png](https://img.kuizuo.cn/2024%2F0930171342-imageundefined1.png)

至此 next.js 的 api 接口都将由 hono.js 来接管，接下来只需要按照 Hono 的开发形态便可。

## 数据效验

zod 可以说是 TS 生态下最优的数据验证器，hono 的 `@hono/zod-validator` 很好用，用起来也十分简单。

```jsx
import { z } from 'zod'
import { zValidator } from '@hono/zod-validator'
import { Hono } from 'hono'

const paramSchema = z.object({
  id: z.string().cuid(),
})

const jsonSchema = z.object({
  status: z.boolean(),
})

const app = new Hono().put(
  '/users/:id',
  zValidator('param', paramSchema),
  zValidator('json', jsonSchema),
  (c) => {
    const { id } = c.req.valid('param')
    const { status } = c.req.valid('json')

    // 逻辑代码...

    return c.json({})
  },
)

export default app
```

支持多种验证目标(param,query,json,header 等)，以及 TS 类型完备，这都不用多说。

但此时触发数据验证失败，响应的结果令人不是很满意。下图为访问 `/api/todo/xxx` 的响应结果（其中 xxx 不为 cuid 格式，因此抛出数据验证异常)

![image.png](https://img.kuizuo.cn/2024%2F0930171510-imageundefined2.png)

所返回的响应体是完整的 zodError 内容，并且状态码为 400

:::tip

数据验证失败的状态码通常为 **[422](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/422)**

:::

因为 zod-validator 默认以 json 格式返回整个 result，代码详见 [zod-validator/src/index.ts#L68-L70](https://github.com/honojs/middleware/blob/main/packages/zod-validator/src/index.ts#L68-L70)

这就是坑点之一，返回给客户端的错误信息肯定不会是以这种格式。这里我将其更改为全局错误捕获，做法如下

1. 复制 [zod-validator 文件](https://github.com/honojs/middleware/blob/main/packages/zod-validator/src/index.ts)并粘贴至 `server/api/validator.ts`，并将 return 语句更改为 throw 语句。

```diff
   if (!result.success) {
-    return c.json(result, 400)
   }

   if (!result.success) {
+    throw result.error
   }
```

2. 在 `server/api/error.ts` 中，编写 handleError 函数用于统一处理异常。（后文前端请求也需要统一处理异常）

```tsx
import { z } from 'zod'
import type { Context } from 'hono'
import { HTTPException } from 'hono/http-exception'

export function handleError(err: Error, c: Context): Response {
  if (err instanceof z.ZodError) {
    const firstError = err.errors[0]

    return c.json(
      { code: 422, message: `\`${firstError.path}\`: ${firstError.message}` },
      422,
    )
  }

  // handle other error, e.g. ApiError

  return c.json(
    {
      code: 500,
      message: '出了点问题, 请稍后再试。',
    },
    { status: 500 },
  )
}
```

3. 在 `server/api/index.ts` ，也就是 hono app 对象中绑定错误捕获。

```tsx
const app = new Hono().basePath('/api')

app.onError(handleError)
```

4. 更改 zValidator 导入路径。

```diff
- import { zValidator } from '@hono/zod-validator'

+ import { zValidator } from '@/server/api/validator'
```

这样就将错误统一处理，响应体也自定义，且后续自定义业务错误也同样如此。

![](https://img.kuizuo.cn/2024%2F1003095801-20241003095800.png)

:::note 顺带一提

如果需要让 zod 支持中文错误提示，可以使用 [zod-i18n-map](https://www.npmjs.com/package/zod-i18n-map)

:::

## RPC

Hono 有个特性我很喜欢也很好用，可以像 [TRPC](https://trpc.io/) 那样，导出一个 [client](https://hono.dev/docs/guides/rpc#client) 供前端直接调用，省去编写前端 api 调用代码以及对应的类型。

这里我不想在过多叙述 RPC(可见我之前所写有关 [TRPC 的使用](https://kuizuo.cn/blog/typescript-full-stack-technology-trpc#end-to-end-typesafe-apis%E7%AB%AF%E5%88%B0%E7%AB%AF%E7%B1%BB%E5%9E%8B%E5%AE%89%E5%85%A8))，直接来说说有哪些注意点。

### 链式调用

还是以 User CRUD 的代码为例，不难发现 `.get` `.post` `.put` 都是以链式调用的写法来写的，一旦拆分后，此时接口还是能够调用，但这将会丢失此时路由对应的类型，导致 client 无法使用获取正常类型，使用链式调用的 app 实例化对象则正常。

![image.png](https://img.kuizuo.cn/2024%2F0930171730-imageundefined3.png)

### 替换原生 Fetch 库

hono 自带的 fetch 或者说原生的 fetch 非常难用，为了针对业务错误统一处理，因此需要选用请求库来替换，这里我的选择是 [ky](https://www.npmjs.com/package/ky)，因为他的写法相对原生 fetch 更友好一些，并且不会破坏 hono 原有类型推导。

在 `lib/api-client.ts` 编写以下代码

```tsx
import { AppType } from '@/server/api'
import { hc } from 'hono/client'
import ky from 'ky'

const baseUrl =
  process.env.NODE_ENV === 'development'
    ? 'http://localhost:3000'
    : process.env.NEXT_PUBLIC_APP_URL!

export const fetch = ky.extend({
  hooks: {
    afterResponse: [
      async (_, __, response: Response) => {
        if (response.ok) {
          return response
        } else {
          throw await response.json()
        }
      },
    ],
  },
})

export const client = hc<AppType>(baseUrl, {
  fetch: fetch,
})
```

这里我是根据请求状态码来判断本次请求是否为异常，因此使用 response.ok，而响应体正好有 message 字段可直接用作 Error message 提示，这样就完成了前端请求异常处理。

至于说请求前自动添加协议头、请求后的数据转换，这就属于老生常谈的东西了，这里就不多赘述，根据实际需求编写即可。

### 请求体与响应体的类型推导

配合 react-query 可以更好的获取类型安全。此写法与 tRPC 十分相似，相应代码 → [Inferring Types](https://trpc.io/docs/client/react/infer-types)

```tsx
// hooks/users/use-user-create.ts

import { client } from '@/lib/api-client'
import { InferRequestType, InferResponseType } from 'hono/client'
import { useMutation } from '@tanstack/react-query'
import { toast } from 'sonner'
const $post = client.api.users.$post

type BodyType = InferRequestType<typeof $post>['json']

type ResponseType = InferResponseType<typeof $post>['data']

export const useUserCreate = () => {
  return useMutation<ResponseType, Error, BodyType>({
    mutationKey: ['create-user'],
    mutationFn: async (json) => {
      const { data } = await (await $post({ json })).json()

      return data
    },
    onSuccess: (data) => {
      toast.success('User created successfully')
    },
    onError: (error) => {
      toast.error(error.message)
    },
  })
}
```

在 `app/users/page.tsx` 中的使用

```tsx
'use client'

import { useUserCreate } from '@/features/users/use-user-create'

export default function UsersPage() {
  const { mutate, isPending } = useUserCreate()

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)
    const name = formData.get('name') as string
    const email = formData.get('email') as string
    mutate({ name, email })
  }

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label htmlFor='name'>Name:</label>
        <input type='text' id='name' name='name' />
      </div>
      <div>
        <label htmlFor='email'>Email:</label>
        <input type='email' id='email' name='email' />
      </div>
      <button type='submit' disabled={isPending}>
        Create User
      </button>
    </form>
  )
}
```

## OpenAPI 文档

> 这部分我已经弃坑了，没找到一个很好的方式为 Hono 写 OpenAPI 文档。不过对于 TS 全栈开发者，似乎也没必要编写 API 文档（接口自给自足），更何况还有 RPC 这样的黑科技，不担心接口的请求参数与响应接口。

如果你真要写，那我说说几个我遇到的坑，也是我弃坑的原因。

首先就是写法上，你需要将所有的 Hono 替换成 OpenAPIHono (来自 [@hono/zod-openapi](https://www.npmjs.com/package/@hono/zod-openapi)， 其中 zod 实例 z 也是)。以下是官方的[示例代码](https://hono.dev/examples/zod-openapi)，我将其整合到一个文件内

```tsx
import { createRoute, OpenAPIHono, z } from '@hono/zod-openapi'
import { swaggerUI } from '@hono/swagger-ui'

const app = new OpenAPIHono()

const ParamsSchema = z.object({
  id: z
    .string()
    .min(3)
    .openapi({
      param: {
        name: 'id',
        in: 'path',
      },
      example: '123',
    }),
})

const UserSchema = z
  .object({
    id: z.string().openapi({ example: '123' }),
    name: z.string().openapi({ example: 'John Doe' }),
  })
  .openapi('User')

const route = createRoute({
  method: 'get',
  path: '/api/users/{id}',
  request: {
    params: ParamsSchema,
  },
  responses: {
    200: {
      content: {
        'application/json': {
          schema: UserSchema,
        },
      },
      description: 'Retrieve the user',
    },
  },
})

app.openapi(route, async (c) => {
  const { id } = c.req.valid('param')

  // 逻辑代码...
  const user = {
    id,
    name: 'Ultra-man',
  }

  return c.json(user)
})
```

从上述代码的可读性来看，第一眼你很难看到清晰的看出这个接口到底是什么请求方法、请求路径，并且在写法上需要使用 `.openapi` 方法，传入一个由 createRoute 所创建的 router 对象。并且写法上不是在原有基础上扩展，已有的代码想要通过[代码优先](https://apifox.com/blog/api-first-api-design-first-or-code-first/)的方式来编写 OpenAPI 文档将要花费不小的工程，这也是我为何不推荐的原因。

定义完接口(路由)之后，只需要通过 app.doc 方法与 swaggerUI 函数，访问 /api/doc 查看 OpenAPI 的 JSON 数据，以及访问 /api/ui 查看 Swagger 界面。

```jsx
import { swaggerUI } from '@hono/swagger-ui'

app.doc('/api/doc', {
  openapi: '3.0.0',
  info: {
    version: '1.0.0',
    title: 'Demo API',
  },
})

app.get('/api/ui', swaggerUI({ url: '/api/doc' }))
```

![image.png](https://img.kuizuo.cn/2024%2F0930171730-imageundefined4.png)

从目前来看，OpenAPI 文档的生成仍面临挑战。我们期待 Hono 未来能推出一个功能，可以根据 app 下的路由自动生成接口文档（相关[Issue](https://github.com/honojs/hono/issues/2970)已存在）。

## 仓库地址

附上本文中示例 demo 仓库链接（这个项目就不搞线上访问了）

https://github.com/kuizuo/nextjs-with-hono

## 后记

其实我还想写写 Auth、DB 这些服务集成的(这些都在我实际工作中实践并应用了)，或许是太久未写 Blog 导致手生了不少，这篇文章也是断断续续写了好几天。后续我将会出一版完整的我个人的 Nextjs 与 Hono 的最佳实践模版。

也说说我为什么会选用 Hono.js 作为后端服务, 其实就是 Next.js 的 API Route 实在是太难用了，加之轻量化，你完全可以将整个 Nextjs + Hono 服务部署在 Vercel 上，并且还能用上 [Edge Functions](https://vercel.com/docs/functions) 的特性。(就是有点小贵)

但不过从我的 Nest.js 开发经验来看（也可能是习惯了 Spring Boot 那套三层架构开发形态），总觉得 Hono 差了点意思，说不出来的体验，可能这就是所谓的全栈框架的开发感受吧。
