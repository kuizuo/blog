---
slug: restful-api-url-definition
title: 关于 restful api 路径定义的思考
date: 2023-11-30
authors: kuizuo
tags: [杂谈, restful]
keywords: [杂谈, restful]
---

关于 restful api 想必不用多说，已经有很多文章都阐述过它的设计原则，但遵循这个原则可以让你的 API 接口更加规范吗？以下是我对 restful api 风格的一些思考🤔。

<!-- truncate -->

## 思考

此时不妨思考一个问题，现在以下几个接口，你会怎么去设计 url 路径？

- 查询文章
- 查看文章详情
- 创建文章
- 更新文章
- 删除文章
- 查看我的文章
- 查看他人的文章

前 5 个接口想必不难设计，这边就给出标准答案。

- 查询文章 `GET /articles`
- 查看某篇文章详情 `GET /articles/:id`
- 创建文章 `POST /articles/`
- 更新文章 `PUT /articles/:id`
- 删除文章 `DELETE /articles/:id`

当然，我相信肯定也有`GET /article—list` `POST /add-article` 这样的答案，不过这些不在 restful api 风格的范畴，就不考虑了。

而这时 查看我的文章 或许就需要稍加思考，或许你会有以下几种方式

- `GET /my-articles` 从资源角度来看肯定不好，因为此时在 url 不能很直观地体现请求资源，同时在控制器文件(controller) 就与 article 分离了，并且还占用了 / 下路径。
- `GET /articles/mine` 则又不那么遵循 restful api 风格，挺违和的。

那么这时不妨遵循 **资源从属关系**，在这里 文章所属的对象就用户，因此查看他人的文章可以这么设计`GET /users/:userId/articles` 获取特定用户（userId）的文章列表。

而 查看我的文章 同样也可用此 URL，只需将 userId 更改为自己的便可。从 api 的 URL 来看是很舒服了，但是从代码开发的角度上问题又有了问题了。。。

对于 user 资源，是不是也有查询，创建，更新，删除等接口，即 查询用户 `GET /users`，创建用户`POST /users/` 等等。。

我是不是就需要在 user 这么重要的资源控制器上去添加一些其他方法，所对应的代码就如下所示

```jsx
@Controller('users')
export class UserController {
  constructor(private userService: UserService, private articleService: ArticleService) {}

  @Get()
  async list(@Query() dto: UserQueryDto) {
    return this.userService.findAll(dto)
  }

  @Get(':id')
  async info(@Param('id') id: number) {
    return this.userService.findOne(id)
  }

  @Post()
  async create(@Body() dto: UserCreateDto) {
    await this.userService.create(dto)
  }

  // 省略有关 User 部分接口，以下是其他 user 下的资源接口

  @Get(':userId/articles')
  async articles(@Param('userId') userId: number) {
    return this.userService.findAll(userId, articlesId)
  }

  @Get(':userId/articles/:articlesId')
  async articles(@Param('userId') userId: number, @Param('articlesId') articlesId: number) {
    return this.articleService.find(userId, articlesId)
  }
}
```

换做是我，肯定不会希望将用户的代码与文章的代码混杂在一起。解决办法也是有的，可以额外创建一个新的 UserController 文件，专门用于获取用户下的资源（这里指 article），这样可以 即与原有针对 user 资源进行解耦，有可以有比较清晰接口分类。

:::warning

不过针对这种情况我可能的解决办法是下会额外 **起一个别名**，例如 author，将 `/users/:id/articles`转为 `/authors/:id/articles`，不过在这里指向的是用户 id，而不是新建一个 author 实体（资源）。

这里的 id 会根据情况而定，假设业务中需要创建 author 实体的情况下，对 author（作者）这一身份有一些操作，如普通用户变成一个作者，获取所有作者，那么这么做就再适合不过了。

在比如说一个更鲜明的例子 商店(store) 与 商品(product)。

:::

业务再稍微复杂一下，现在要为业务增加以下几个功能，你又会如何设计

- 收藏他人文章
- 获取我收藏的文章

答案应该会有两种，即 `POST /articles/:articleId/collections` 与 `POST /collections`

而这就令我特别头疼，因为这两个都符合 restful api 风格，也确实都能很好的满足业务功能。于是在我尝试抓包拥有相关的网站后，我发现几乎都是后者的 url。后来一想，前者更像是获取某种资源，而不是用于创建资源。后者确实更能胜任多数场景，比如说现在我需要收藏某个专栏，那么我用 `POST /collections` 足以胜任，只需要传递 条目id与条目类型，后端根据这两个条件找到对应条目数据便可。假设后续业务多一个资源需要收藏也不成问题。但换做前者的话，就得再多写一个重复性接口。

## 抽象资源

restful 更多是针对实际存储的资源，核心是名词，对于增删改查的业务可以说非常适合，但现实情况下不只有增删改查，就例如上述的收藏功能。

对于一些个别接口需要另外表达，如 登录 `POST /login`、获取个人信息 `GET /profile`

对于一些非增删改查的操作，还是使用 RPC 式的 API 更为实在，即 **`POST /命名空间/资源类型/动作`**，至少不用再为某个操作决定 PATCH/PUT 还是 POST/DELETE。

## 针对同一实体，区分不同用户

问题还没结束，不妨碍继续使用上述文章的例子，针对 文章 这一实体，又要怎么定义（区分）用户与作者或管理员路径呢？

管理员所看到的数据肯定远比用户来的多，如果使用同一个接口（如 `/articles`），那么业务代码必然会十分复杂。

使用不同的端点(end point) 是个解决方法，例如管理员在请求前添加 manage 或 admin，如 `/manage/articles` 或 `/articles/manage` 这样只需要多一步判断请求用户是否拥有管理的权限。

但对我个人而言，我一般都会以在一个命名空间下（这里指 `/articles`）编写，像前面的 `/manage/articles` 我是直接 pass 的。

在设计接口的原则就优先以拥有者的身份来设计，在去设计其他用户获取这个资源的接口。就比如说上述 `article` 为例， 针对增删改查而言，都是用于这个资源的拥有者可操作的，那么所获取到的数据就是尽可能符合拥有者需求的。而这时如果要将资源给其他角色请求，就会根据情况设计，如

- `GET /articles` 获取我的文章列表（针对拥有者）
- `GET /articles/query` 查询文章（针对所有用户）

## 权限区分

在 restful 中有两个概念：resources 与 action，因此只需要定义好权限标识码便可，还是以文章举例，如 `article:read` `article:create` `article:update` `article:delete` ，这里的 resources 对应的就是 article ，action 则是 read，create 等。将这些权限码分配给不同的控制器方法，在某个请求的时候判断用户是否拥有这个权限码便可。

## 资源粒度问题

但是复杂的实际业务中，仅仅单靠 restful API，往往需要发送多条请求，例如获取某篇文章数据与作者数据

```
GET /articles/1

GET /articles/1/author
```

要么两条请求获取相应数据，要么为调用方“定制”一个接口，如`GET /getArticleInfo`，这样只需一条请求便可得到想要的数据。但这个就破坏了 restful API 接口风格，并且在复杂的业务中，比如说还要获取博文的评论等等，后端就要额外提供一个接口，可以说是非常繁琐了。相比之下 [GraphQL](https://graphql.org/) 就更为灵活了。

## 最佳实践

就在我写完这篇文章的几周后,无意间刷到了这篇文章[examples-of-great-urls/](https://blog.jim-nielsen.com/2023/examples-of-great-urls/)

借用这个文章以及我自身实现,说说我个人认为的最佳实践.

## 写到最后

在我写这篇文章之前，我尝试抓包看过很多网站的请求 url，见识到各式各样的 url 路径，基本上很难找到遵循 restful api 风格的网站，绝大多数的操作除了获取外用 GET，其余全用 POST 。对于复杂的业务，restful api 风格实在过于难以胜任。

如果说变量命名是编程最大的痛苦，那么写接口最大的痛苦我想就是定义 url 路径了。

## 相关文章

[RESTful API 对于同一实体，如何定义管理员和用户的路径？](https://www.v2ex.com/t/482682)

[RESTful API设计经验总结](https://blog.51cto.com/LiatscBookshelf/5427906)

[为什么很多后端写接口都不按照 restful 规范？](https://www.zhihu.com/question/438825740)
