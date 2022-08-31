---
slug: next.js-build-and-deploy
title: Next.js项目搭建与部署
date: 2022-07-13
authors: kuizuo
tags: [next, react, ssr, vercel]
keywords: [next, react, ssr, vercel]
---

<!-- truncate -->

官方文档 [Getting Started | Next.js (nextjs.org)](https://nextjs.org/docs/getting-started)

## [安装](https://nextjs.org/docs/getting-started#automatic-setup)

```sh
npx create-next-app@latest --ts
# or
yarn create next-app --typescript
# or
pnpm create next-app --ts
```

运行

```
npm run dev
```

访问 http://localhost:3000

## 项目结构

![image-20220712030637300](https://img.kuizuo.cn/image-20220712030637300.png)

| 文件           | 内容                 |
| -------------- | -------------------- |
| pages          | 页面文件             |
| pages/api      | api 数据接口         |
| public         | 静态资源文件         |
| styles         | 样式文件             |
| next-env.d.ts  | 确保 typescript 支持 |
| next.config.ts | next 配置文件        |

## 路由

nextjs 有一个基于页面概念的文件系统路由器，存放在 pages 下`.js`, `.jsx`, `.ts`, `.tsx` 文件都将作为组件，即**文件路径 → 页面路由**，例如这里的 index.tsx 映射为 index，`pages/about.js` 将映射为 `/about`。

同时还支持动态路由，创建`pages/user/[id].tsx`文件，然后访问`user/1`，`user/2`

```tsx title="[id].tsx"
import { useRouter } from 'next/router'

const User = () => {
  const router = useRouter()
  const { id } = router.query

  return <div>User id:{id} </div>
}

export default User
```

此时访问 http://localhost:3000/user/1 便可得到 `User ID: 1`

在 router 对象下没有 param 属性，都是存放在 query 参数中，例如访问 user/1?username=kuizuo，此时的 query 值为 `{username: 'kuizuo', id: '2'}`

:::tip

不过这里有个比较有意思的点，如果你在上方代码中使用 console.log 打印 query 的话，在 vscode 中会打印出空对象`{}`，而在浏览器中会打印一次空对象，一次真实的 query 对象（并且打印两遍）

![image-20220712191356587](https://img.kuizuo.cn/image-20220712191356587.png)

:::

## 数据渲染

如果你打开控制台，查看所返回的页面，你会发现响应中只有 User id:，这不就和 react 的 CSR(客户端)渲染没有区别吗，是的，确实是这样。因为上一部分的代码，并且从输出 query 也可以看的出来而不是 SSR(服务端)渲染。首先我要展示一下两者渲染的代码

### CSR 客户端渲染

```tsx title="[id].tsx"
import { useEffect, useState } from 'react'
import { useRouter } from 'next/router'

const User = () => {
  const router = useRouter()
  const { id } = router.query

  const [data, setData] = useState({
    username: '',
    email: '',
  })

  useEffect(() => {
    fetch(`https://jsonplaceholder.typicode.com/users/${id}`)
      .then((res) => res.json())
      .then((data) => {
        setData(data)
      })
      .catch((err) => {})
  }, [id])

  return (
    <div>
      <p>username:{data.username} </p>
      <p>email:{data.email} </p>
    </div>
  )
}

export default User
```

经常写 react 的肯定对上面的代码不陌生，前端向后端发送数据请求，接受到数据后赋值给 data，然后渲染出来。因为请求数据是需要耗时的，所以在页面显示完之后，会停顿一会在显示出数据（主要是我这边没写 loadding），并且由于 id 并不是第一时间获取到的（从上面的 id）。

![image-20220712193009186](https://img.kuizuo.cn/image-20220712193009186.png)

从这里来看，客户端渲染不仅要获取页面组件，还要请求数据，最终再通过 js 渲染出来

### SSR 服务端渲染

next 中服务端渲染需要用到 getServerSideProps 函数，而后端的数据获取都是在该函数内来获取，并通过 prop 传入给前端组件中，来看实际代码

```tsx title="[id].tsx"
const User = ({ data }: { data: any }) => {
  return (
    <div>
      <p>username:{data.username} </p>
      <p>email:{data.email} </p>
    </div>
  )
}

export default User

export async function getServerSideProps(context: { query: { id: any } }) {
  const { id } = context.query // 这里context.param也能获取到id

  const res = await fetch(`https://jsonplaceholder.typicode.com/users/${id}`)

  const data = await res.json()

  return {
    props: {
      data,
    },
  }
}
```

如果从页面显示来看，确实没什么区别，但如果打开控制台就能发现诸多不同。

首先就是请求的页面，是直接包含数据，相当于返回你一个页面，而在客户端渲染则是返回一个组件，需要自己去请求数据来展示。

![image-20220712192713634](https://img.kuizuo.cn/image-20220712192713634.png)

同时查看控制台中的 Fetch/XHR 的是看不到请求的数据，因为这些数据并不是由前端发送的,而是由后端发送的（故不受跨域请求的限制）。

从这就能看出客户端渲染与服务端渲染的的区别了。

### SSG 静态生成

不过还没完，还有一个静态生成，先来看看代码。

```tsx title="[id].tsx"
const User = ({ data }: { data: any }) => {
  return (
    <div>
      <p>username:{data.username} </p>
      <p>email:{data.email} </p>
    </div>
  )
}

export default User

export async function getStaticProps(context: { params: { id: any } }) {
  const { id } = context.params

  const res = await fetch(`https://jsonplaceholder.typicode.com/users/${id}`)

  const data = await res.json()

  return {
    props: {
      data,
    },
  }
}

export async function getStaticPaths() {
  return {
    paths: new Array(20).fill(0).map((a, i) => ({ params: { id: String(i + 1) } })),
    fallback: 'blocking',
  }
}
```

主要是 getServerSideProps 替换成 getStaticProps，同时增加了一个 getStaticPaths 用于生成静态页面的，而上面的 getStaticPaths 表示生成 id 1 到 20 的页面，那假设如果我访问 id 为 21 的 user 呢？由于这里设置`fallback: 'blocking'`，所以还是会走服务端渲染的那一部分。但如果设置`fallback: fasle`，访问 user/21 就会提示 404。

通俗点来说就就是生成一系列静态页面，不需要服务端处理，所以返回的速度更快，其缺点其实也比较明显，数据的任何更改都需要在服务端重新构建，而服务端渲染则是可以动态处理数据，不需要完全重建。

### ISR 增量式静态生成

不做过多介绍，详看文档 [Data Fetching: Incremental Static Regeneration | Next.js (nextjs.org)](https://nextjs.org/docs/basic-features/data-fetching/incremental-static-regeneration)

## api 接口

上面的数据都是调用 [JSONPlaceholder](http://jsonplaceholder.typicode.com/) 所提供的虚拟数据，在 next 中要提供数据接口的话，只需要在 pages/api 下编写即可，生成的路由规则和组件一样。例如 pages/api/hello.ts 映射为 api/hello，浏览器访问[http://localhost:3000/api/hello](http://localhost:3000/api/hello) 就可以得到`{"name": "John Doe"}`

```tsx title="hello.ts"
import type { NextApiRequest, NextApiResponse } from 'next'

type Data = {
  name: string
}

export default function handler(req: NextApiRequest, res: NextApiResponse<Data>) {
  res.status(200).json({ name: 'John Doe' })
}
```

这里的 req、res 就是同大部分 node 后端框架一样，而这里的写法与 serverless 一致（这里应该就是 serverless）。

上述是 get 请求，那 post 请求呢？无论什么 http 请求方法都将在 handler 处理，通过 req.method 来获取请求方法，要区分的话可以通过如下代码。

```tsx
export default function handler(req, res) {
  if (req.method === 'POST') {
    // Process a POST request
  } else {
    // Handle any other HTTP method
  }
}
```

### 写一个简单的 CRUD

既然知道了上述的一些作用，不妨来个熟悉的 CRUD。这里以文章 post 为例

这里数据端使用的时 sqlite，配置不做展示，只展示主要核心功能

```typescript title="api/post/index.ts"
import type { NextApiRequest, NextApiResponse } from 'next'
import db from '../../../lib/db'

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    switch (req.method) {
      case 'GET':
        db.all(`select * from post`, (err, rows) => {
          res.status(200).json(rows)
        })
        break
      case 'POST':
        const { title, content } = req.body

        db.get(`insert into post(title, content) values(?, ?)`, [title, content], (err, rows) => {
          res.status(200).json(rows)
        })
        break
    }
  } catch (error) {
    res.status(500).end()
  }
}
```

```typescript title="api/post/[id].ts"
import type { NextApiRequest, NextApiResponse } from 'next'
import db from '../../../lib/db'

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const { id } = req.query
  const { title, content } = req.body

  try {
    switch (req.method) {
      case 'GET':
        db.get(`select * from post where id=$id`, { $id: id }, (err, rows) => {
          res.status(200).json(rows)
        })
        break
      case 'Put':
        db.get(`update post set title=?,content=? where id=?`, [title, content, id], (err, rows) => {
          res.status(200).json(rows)
        })
      case 'DELETE':
        db.get(`delete from post where id=$id`, { $id: id }, (err, rows) => {
          res.status(200).json(rows)
        })
    }
  } catch (error) {
    res.status(500).end()
  }
}
```

这里为了符合 RESTFUL 风格，所以 post 下编写了两个文件，这时候请求[http://localhost:3000/api/post](http://localhost:3000/api/post/2) 就能获取到所有文章数据，基本的 CRUD 也就实现了。

这里写 sql 是真滴繁琐，没使用 str 或是 typeorm 主要是不想把这个 demo 搞得太复杂，实际项目还是用上比较好。

当然这里只是作为后端 api 接口的演示，至于前端的展示与编写就和普通前端开发没啥大的区别。基本后端框架能做的，next 能做后端很多事情，更多的使用还是作为接口转发，中间件等，毕竟 Next 主要的强项还是服务端渲染的能力。

## 打包部署

既然说到部署，那肯定离不开 nextjs 的母公司[Vercel](https://vercel.com)了，关于 Vercel 之前也写过相关文章，关于 Vercel 就不过多介绍。

nextjs 部署到 vercel 实在简单，将项目推送到 github 仓库中，然后在 vercel 中 New Project，接着选择 nextjs 的仓库，点击 Deploy，静等部署即可。关于部署可以看这篇文章 [Vercel 部署个人博客](https://kuizuo.cn/develop/Vercel部署个人博客)

现在你可以通过访问 [kz-next-app-demo.vercel.app](https://kz-next-app-demo.vercel.app/) 来访问该项目，并尝试访问`/api/post`，`user/1`来看看。

只能说不愧是母公司。

至于其他部署？既然都用 nextjs 了，还考虑自建服务器来部署吗？

## 总结

这次的整体过程比较简单，后续应该会使用 nextjs 编写一个完整的项目（~~也有可能是 nuxt.js~~)。
