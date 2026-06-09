---
slug: graphql-practice
title: GraphQL 实践与服务搭建
date: 2022-11-24
authors: kuizuo
tags: [api, graphql, nest, strapi]
keywords: [api, graphql, nest, strapi]
description: 有关 GraphQL 介绍及上手实践，并在 Nest.js 和 Strapi 中搭建 GraphQL 服务
---

> GraphQL 既是一种用于 API 的查询语言也是一个满足你数据查询的运行时。 GraphQL 对你的 API 中的数据提供了一套易于理解的完整描述，使得客户端能够准确地获得它需要的数据，而且没有任何冗余，也让 API 更容易地随着时间推移而演进，还能用于构建强大的开发者工具。

大概率你听说过 GraphQL，知道它是一种与 Rest API 架构属于 API 接口的查询语言。但大概率你也与我一样没有尝试过 GraphQL。

事实上从 2012 年 Facebook 首次将 GraphQL 应用于移动应用，到 GraphQL 规范于 2015 年实现开源。可如今现状是 GraphQL 不温不火，时不时又有新的文章介绍，不知道的还以为是什么新技术。

:::tip[目标]

本文将上手使用 GraphQL，并用 Nestjs 与 Strapi 这两个 Node 框架搭建 GraphQL 服务。

:::

{/* truncate */}

关于 GraphQL 介绍，详见官网 [GraphQL | A query language for your API](https://graphql.cn/ 'GraphQL | A query language for your API') 或相关介绍视频 [GraphQL 速览：React/Vue 的最佳搭档](https://www.bilibili.com/video/BV1fM4y1A7U1/ 'GraphQL 速览：React/Vue 的最佳搭档')

## GraphQL 与 Restful API 相比

![](https://img.kuizuo.me/9a7412200a062646b729c8419be28b35.jpeg)

### Restful API

Restful 架构的设计范式侧重于分配 HTTP 请求方法（GET、POST、PUT、PA TCH、DELETE）和 URL 端点之间的关系。如下图

![](https://img.kuizuo.me/17fc41e2de8d829dc2d41e31a0775df3.png)

但是实际复杂的业务中，单靠 Restful 接口，需要发送多条请求，例如获取博客中某篇博文数据与作者数据

```http
GET /blog/1

GET /blog/1/author
```

要么单独另写一个接口，如`getBlogAndAuthor`，这样直接为调用方“定制”一个接口，请求一条就得到就调用方想要的数据。但是另写一个`getBlogAndAuthor` 就破坏了 Restful API 接口风格，并且在复杂的业务中，比如说还要获取博文的评论等等，后端就要额外提供一个接口，可以说非常繁琐了。

有没有这样一个功能，将这些接口做一下聚合，然后**将结果的集合返回给前端**呢？在目前比较流行微服务架构体系下，有一个专门的中间层专门来处理这个事情，这个中间层叫 BFF（Backend For Frontend）。可以参阅 [BFF——服务于前端的后端](https://blog.csdn.net/qianduan666a/article/details/107271974 'BFF——服务于前端的后端')

![](https://img.kuizuo.me/Y4u9tNpZwR.png)

但这些接口一般来说都比较重，里面有很多当前页面并不需要的字段，那还有没有一种请求：**客户端只需要发送一次请求就能获取所需要的字段**

有，也就是接下来要说的 GraphQL

### GraphQL

![](https://img.kuizuo.me/8a141ec5fa73781d66fb2e1b60f9b49d.jpg)

REST API 构建在请求方法（method）和端点（endpoint）之间的连接上，而 GraphQL API 被设计为只通过一个端点，即 `/graphql`，始终使用 POST 请求进行查询，其集中的 API 如 http://localhost:3000/graphql，所有的操作都通过这个接口来执行，这会在后面的操作中在展示到。

:::info

但是想要一条请求就能得到客户端想要的数据字段，那么服务端必然要做比较多的任务 😟（想想也是，后端啥都不干，前端就啥都能获取，怎么可能嘛）。

而服务端要做的就是搭建一个 GraphQL 服务，这在后面也会操作到，也算是本文的重点。

:::

接下来便会在客户端中体验下 GraphQL，看看 GraphQL 究竟有多好用。

## **在线体验 GraphQL**

可以到 [官网](https://graphql.cn/learn/ '官网') 中简单尝试入门一下，在 [Studio](https://studio.apollographql.com/sandbox/explorer 'Studio (apollographql.com)') 可在线体验 GraphQL，也可以到 [SWAPI GraphQL API](<https://swapi-graphql.netlify.app/?query={ person(personID: 1) { name } }> 'SWAPI GraphQL API (swapi-graphql.netlify.app)') 中体验。

下面以 `apollographql` 为例，并查询 People 对象。

### query

查询所有 People 并且只获取 `name`、`gender`、`height` 字段

![](https://img.kuizuo.me/kvWUNtlUbf.png)

查询 personID 为 1 的 Person 并且只获取 `name`，`gender`，`height` 字段

![](https://img.kuizuo.me/Msg9xwWFrl.png)

查询 personID 为 2 的 Person 并且只获取 `name`，`eyeColor`、`skinColor`、`hairColor` 字段

![](https://img.kuizuo.me/hX0l36Acme.png)

从上面查询案例中其实就可以发现，我只需要在 person 中写上想要获取的字段，GraphQL 便会返回带有该字段的数据。避免了返回结果中不必要的数据字段。

```graphql
{
	person{
		# 写上想获取的字段
	}
}
```

如果你不想要 person 数据或者想要其他其他的数据，不用像 Restful API 那样请求多条接口，依旧请求`/graphql`，如

![](https://img.kuizuo.me/Z0b6ya-auG.png)

:::info

**无论你想要什么数据，一次请求便可满足。**

:::

### mutation

GraphQL 的大部分讨论集中在数据获取（也是它的强项），但是任何完整的数据平台也都需要一个改变服务端数据的方法。即 CRUD。

GraphQL 提供了 [变更(Mutations)](https://graphql.cn/learn/queries/#mutations '变更（Mutations）') 用于改变服务端数据，不过 `apollographql` 在线示例中并没有如 `createPeople` 字段支持 。这个片段在线体验中就无法体验到，后在后文中展示到。这里你只需要知道 GraphQL 能够执行基本的 CRUD 即可。

### fragmen 和 subscribtion

此外还有 `fragment ` 与 `subscription` 就不做介绍。

### 小结

尝试完上面这些操作后，可以非常明显的感受到 GraphQL 的优势与便利，本来是需要请求不同的 url，现在只需要请求 `/graphql`，对调用方（前端）来说非常友好，香是真的香。

可目前只是使用了别人配置好的 GraphQL 服务，让前端开发用了特别友好的 API。但是，对于后端开发而言，想要提供 GraphQL 服务可就不那么友善了。因为它不像传统的 restful 请求，需要专门配置 GraphQL 服务，而整个过程是需要花费一定的工作量（定义 Schema，Mutations 等等），前面也提到想要一条请求就能得到客户端想要的数据字段，那服务端必然需要额外的工作量。

不仅需要在后端中配置 GraphQL 服务，用于接收 GraphQL 查询并验证和执行，此外前端通常需要 GraphQL 客户端，来方便使用 GraphQL 获取数据，目前实用比较多的是[Apollo Graph](https://www.apollographql.com/platform/ 'Apollo Graph')，不过本文侧重搭建 GraphQL 服务，因此前端暂不演示如何使用 GraphQL。

你可能听过一句话是，**graphq​l 大部分时间在折磨后端**，并且要求比较严格的数据字段，但是好处都是前端。把工作量基本都丢给了后端，所以在遇到使用这门技术的公司，尤其是后端岗位就需要考虑有没有加班的可能了。

以下便会开始实际搭建 GraphQL 服务，这里会用 Nest.js 与 Strapi 分别实践演示。

## Nest.js

官方文档：[GraphQL + TypeScript | NestJS](https://docs.nestjs.com/graphql/quick-start 'GraphQL + TypeScript | NestJS')

模块：[nestjs/graphql](https://github.com/nestjs/graphql 'nestjs/graphql')

仓库本文实例代码仓库： [kuizuo/nest-graphql-demo](https://github.com/kuizuo/nest-graphql-demo 'kuizuo/nest-graphql-demo')

**创建项目**

```bash
nest new nest-graphql-demo
```

**安装依赖**

```bash
npm i @nestjs/graphql @nestjs/apollo graphql apollo-server-express
```

**修改 app.module.ts**

```typescript title='app.module.ts' icon='logos:nestjs'
import { Module } from '@nestjs/common'
import { GraphQLModule } from '@nestjs/graphql'
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo'

@Module({
  imports: [
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: true,
    }),
  ],
})
export class AppModule {}
```

### resolver

设置了`autoSchemaFile: true` ，nest.js 将会自动搜索整个项目所有以 `.resolver.ts` 为后缀的文件，将其解析为 `schema.gql` 比如说创建`app.resolver.ts`

```typescript title='app.resolver.ts' icon='logos:nestjs'
import { Resolver, Query } from '@nestjs/graphql'

@Resolver()
export class AppResolver {
  @Query(() => String) // 定义一个查询,并且返回字符类型
  hello() {
    return 'hello world'
  }
}
```

在 `graphql` 中 `resolver` 叫解析器，与 `service` 类似（也需要在 `@Module` 中通过 `providers` 导入）。`resolver`主要包括`query`(查询数据)、`mutation`(增、删、改数据)、`subscription`(订阅，有点类型 `socket`)，在 `graphql` 项目中我们用 `resolver` 替换了之前的控制器。

这时候打开[http://127.0.0.1:3000/graphql](http://127.0.0.1:3000/graphql 'http://127.0.0.1:3000/graphql')，可以在右侧中看到自动生成的 Schema，这个 Schema 非常关键，决定了你客户端能够请求到什么数据。

尝试输入 GraphQL 的 query 查询（可以按 Ctrl + i 触发代码建议（Trigger Suggest），与 vscode 同理）

![](https://img.kuizuo.me/a3yl4oVtSU.png)

此时点击执行，可以得到右侧结果，即`app.resolver.ts` 中 `hello` 函数所定义的返回体。

![](https://img.kuizuo.me/bK9bvZ3QMm.png)

### [Code first](https://docs.nestjs.com/graphql/quick-start#code-first) 与 [Schema first](https://docs.nestjs.com/graphql/quick-start#schema-first)

在 nestjs 中有 [Code first](https://docs.nestjs.com/graphql/quick-start#code-first) 与 [Schema first](https://docs.nestjs.com/graphql/quick-start#schema-first) 两种方式来生成上面的 Schema，从名字上来看，前者是优先定义代码会自动生成 Schema，而后者是传统方式先定义 Schema。

在上面一开始的例子中是 Code First 方式，通常使用该方式即可，无需关心 Schema 是如何生成的。下文也会以 Code First 方式来编写 GraphQL 服务。

也可到官方示例仓库中 [nest/sample/31-graphql-federation-code-first](https://github.com/nestjs/nest/tree/master/sample/31-graphql-federation-code-first) 和 [nest/sample/32-graphql-federation-schema-first](https://github.com/nestjs/nest/tree/master/sample/32-graphql-federation-schema-first) 查看两者代码上的区别。

### 快速生成 GraphQL 模块

nest 提供 cli 的方式来快速生成 GraphQL 模块

```typescript
nest g resource <name>
```

![](https://img.kuizuo.me/L9yYAn78Dw.png)

比如创建一个 blog 模块

```bash
nest g resource blog --no-spec
? What transport layer do you use? GraphQL (code first)
? Would you like to generate CRUD entry points? Yes
CREATE src/blog/blog.module.ts (217 bytes)
CREATE src/blog/blog.resolver.ts (1098 bytes)
CREATE src/blog/blog.resolver.spec.ts (515 bytes)
CREATE src/blog/blog.service.ts (623 bytes)
CREATE src/blog/blog.service.spec.ts (446 bytes)
CREATE src/blog/dto/create-blog.input.ts (196 bytes)
CREATE src/blog/dto/update-blog.input.ts (243 bytes)
CREATE src/blog/entities/blog.entity.ts (187 bytes)
UPDATE src/app.module.ts (643 bytes)
```

便会生成如下文件

![](https://img.kuizuo.me/XemqTcfz_D.png)

```typescript title='blog.resolver.ts' icon='logos:nestjs'
import { Resolver, Query, Mutation, Args, Int } from '@nestjs/graphql'
import { BlogService } from './blog.service'
import { Blog } from './entities/blog.entity'
import { CreateBlogInput } from './dto/create-blog.input'
import { UpdateBlogInput } from './dto/update-blog.input'

@Resolver(() => Blog)
export class BlogResolver {
  constructor(private readonly blogService: BlogService) {}

  @Mutation(() => Blog)
  createBlog(@Args('createBlogInput') createBlogInput: CreateBlogInput) {
    return this.blogService.create(createBlogInput)
  }

  @Query(() => [Blog], { name: 'blogs' })
  findAll() {
    return this.blogService.findAll()
  }

  @Query(() => Blog, { name: 'blog' })
  findOne(@Args('id', { type: () => Int }) id: number) {
    return this.blogService.findOne(id)
  }

  @Mutation(() => Blog)
  updateBlog(@Args('updateBlogInput') updateBlogInput: UpdateBlogInput) {
    return this.blogService.update(updateBlogInput.id, updateBlogInput)
  }

  @Mutation(() => Blog)
  removeBlog(@Args('id', { type: () => Int }) id: number) {
    return this.blogService.remove(id)
  }
}
```

此时 Schema 如下

![](https://img.kuizuo.me/sJCQpllOXK.png)

不过`nest cli`创建的`blog.service.ts` 只是示例代码，并没有实际业务的代码。

此外`blog.entity.ts`也不为数据库实体类，因此这里引入`typeorm`，并使用`sqlite3`

### 集成 Typeorm

安装依赖

```bash
pnpm install @nestjs/typeorm typeorm sqlite3
```

```typescript title='app.module.ts' icon='logos:nestjs'
import { Module } from '@nestjs/common'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { GraphQLModule } from '@nestjs/graphql'
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo'
import { AppResolver } from './app.resolver'
import { BlogModule } from './blog/blog.module'
import { TypeOrmModule } from '@nestjs/typeorm'

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'sqlite',
      database: 'db.sqlite3',
      entities: [__dirname + '/**/*.entity{.ts,.js}'],
      synchronize: true,
    }),
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: true,
      playground: true,
    }),
    AppModule,
    BlogModule,
  ],
  controllers: [AppController],
  providers: [AppService, AppResolver],
})
export class AppModule {}
```

将 `blog.entity.ts` 改成实体类，代码为

```typescript title='blog.entity.ts' icon='logos:nestjs'
import { ObjectType, Field } from '@nestjs/graphql'
import { Column, Entity, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm'

@ObjectType()
@Entity()
export class Blog {
  @Field(() => Int)
  @PrimaryGeneratedColumn()
  id: number

  @Field()
  @Column()
  title: string

  @Field()
  @Column({ type: 'text' })
  content: string

  @Field()
  @CreateDateColumn({ name: 'created_at', comment: '创建时间' })
  createdAt: Date

  @Field()
  @UpdateDateColumn({ name: 'updated_at', comment: '更新时间' })
  updatedAt: Date
}
```

其中 `@ObjectType()` 装饰器让 `@nestjs/graphql` 自动让其视为一个 `type Blog`

而 `@Field()` 则是作为可展示的字段，比如 `password` 字段无需返回，就不必要加该装饰器。

:::tip

如果你认为 添加 `@Field()` 是件繁琐的事情（nest 官方自然也想到），于是提供了 [GraphQL + TypeScript - CLI Plugin ](https://docs.nestjs.com/graphql/cli-plugin) 用于省略 `@Field()` 等其他操作。（类似于语法糖）

借用官方的话:

> Thus, you won't have to struggle with @Field decorators scattered throughout the code.

因此，您不必为分散在代码中的 `@Field` 装饰符而烦恼。

:::

`@nestjs/graphql` 会将 typescript 的 number 类型视为 Float，所以需要转成 Int 类型，即 `@Field(() => Int)`

在 BlogService 编写 CRUD 数据库业务代码，并在 dto 编写参数效验代码，这里简单暂时部分代码。

```typescript title='blog.service.ts' icon='logos:nestjs'
import { Injectable } from '@nestjs/common'
import { InjectRepository } from '@nestjs/typeorm'
import { Repository } from 'typeorm'
import { CreateBlogInput } from './dto/create-blog.input'
import { UpdateBlogInput } from './dto/update-blog.input'
import { Blog } from './entities/blog.entity'

@Injectable()
export class BlogService {
  constructor(
    @InjectRepository(Blog)
    private blogRepository: Repository<Blog>,
  ) {}

  create(createBlogInput: CreateBlogInput) {
    return this.blogRepository.save(createBlogInput)
  }

  findAll() {
    return this.blogRepository.find()
  }

  findOne(id: number) {
    return this.blogRepository.findOneBy({ id })
  }

  async update(id: number, updateBlogInput: UpdateBlogInput) {
    const blog = await this.blogRepository.findOneBy({ id })
    const item = { ...blog, ...updateBlogInput }
    return this.blogRepository.save(item)
  }

  remove(id: number) {
    return this.blogRepository.delete(id)
  }
}
```

```typescript title='create-blog.input.ts' icon='logos:nestjs'
import { InputType, Field } from '@nestjs/graphql'

@InputType()
export class CreateBlogInput {
  @Field()
  title: string

  @Field()
  content: string
}
```

此时

![](https://img.kuizuo.me/7-twN56Aym.png)

### CRUD

下面将演示 graphql 的 Mutation。

#### 新增

![](https://img.kuizuo.me/NPqShDN3Pl.png)

#### 修改

![](https://img.kuizuo.me/c4ycwRs-po.png)

#### 删除

![](https://img.kuizuo.me/xpkHhpS1-K.png)

Query 就不在演示。

### 小结

至此，在 Nest.js 中配置 GraphQL 服务的就演示到此，从这里来看，Nest.js 配置 GraphQL 服务还算比较轻松，但是做了比较多的工作量，创建 resolver，创建 modal（或在已有实体添加装饰器），不过本文案例中只演示了基本的 CRUD 操作，实际业务中还需要涉及鉴权，限流等等。

## Strapi

Strapi 官方提供 [GraphQL 插件](https://market.strapi.io/plugins/@strapi-plugin-graphql 'GraphQL插件') 免去了配置的繁琐。更具体的配置参见 [GraphQL - Strapi Developer Documentation](https://docs.strapi.io/developer-docs/latest/development/plugins/graphql.html 'GraphQL - Strapi Developer Documentation')

这里我就选用 [kuizuo/vitesse-nuxt-strapi](https://github.com/kuizuo/vitesse-nuxt-strapi 'kuizuo/vitesse-nuxt-strapi') 作为演示，并为其提供 graphQL 支持。

strapi 安装

```bash
npm install @strapi/plugin-graphql
```

接着启动 strapi 项目，并在浏览器打开 graphql 控制台 [http://localhost:1337/graphql](http://localhost:1337/graphql 'http://localhost:1337/graphql')，以下将演示几个应用场景。

### 例子

#### 查询所有 todo

![](https://img.kuizuo.me/4GFUs8CmQJ.png)

#### 查询 id 为 2 的 todo

![](https://img.kuizuo.me/NMM4e3L_y8.png)

#### 查询 id 为 2 的 todo 并只返回 value 属性

![](https://img.kuizuo.me/E1eWrzjaEs.png)

#### 新增 todo

![](https://img.kuizuo.me/pclR7Zb6TE.png)

#### 更新 todo

![](https://img.kuizuo.me/g3RJL7RQWR.png)

#### 删除 todo

![](https://img.kuizuo.me/m7s17q2TG0.png)

由于 [Nuxt Strapi](https://strapi.nuxtjs.org/ 'Nuxt Strapi') 提供 [useStrapiGraphQL](https://strapi.nuxtjs.org/usage#usestrapigraphql 'useStrapiGraphQL') 可以非常方便是在客户端调用 GraphQL 服务。

```vue
<script setup lang="ts">
const route = useRoute()
const graphql = useStrapiGraphQL()

// Option 1: use inline query
const restaurant = await graphql(`
  query {
    restaurant(id: ${route.params.id}) {
      data {
        id
        attributes {
          name
        }
      }
    }
  }
`)

// Option 2: use imported query
const restaurant = await graphql(query, { id: route.params.id })
</script>
```

### 小结

对于 Strapi 来说，搭建 GraphQL 服务基本没有配置的负担，安装一个插件，即可配合 Strapi 的 content-type 来提供 GraphQL 服务。

## 总结

**GraphQL** 翻译过来为 **图表 Query Language**，我所理解的理念是通过 json 数据格式的方式去写 SQL，而且有种前端人员在写 sql 语句。在我看来 GraphQL 更多是业务数据特别复制的情况下使用，往往能够事半功倍。但对于本文中示例的代码而言，GraphQL 反倒有点过于先进了。

如今看来，GraphQL 还处于不温不火的状态，目前更多的站点主流还是使用 Restful API 架构。我不过我猜测，主要还是大多数业务没有 API 架构的升级的需求，原有的 Restful API 虽说不够优雅，但是也能够满足业务的需求，反而 GraphQL 是一个新项目 API 架构的选择，但不是一个必须的选择。

至于如何选择，可以参阅官方 [GraphQL 最佳实践](https://graphql.cn/learn/best-practices/)，至于说有没有必要学 GraphQL，这篇文章 [都快 2022 年了 GraphQL 还值得学吗](https://blog.csdn.net/kevin_tech/article/details/120735500) 能给你答案。我的建议是了解即可，新项目可以考虑使用，就别想着用 GraphQL 来重构原有的 API 接口，工作量将会十分巨大，并且还可能是费力不讨好的事。反正我认为这门技术不像 Git 这种属于必学的技能，我的五星评分是 ⭐⭐

但多了解一门技术，就是工作面试的资本。回想我为何尝试 GraphQL，就是因为我无意间看到了一份 ts 全栈的远程面试招聘，在这份招聘单中写到 【会 graphql 编写是加分项】。所以抱着这样的态度去尝试了一番，说不准未来就是因为 graphql 让我拿到该 offer。当然也是因为很早之前就听闻 GraphQL，想亲手目睹下是否有所谓的那么神奇。
