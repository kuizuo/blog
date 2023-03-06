---
slug: use-fresh-build-web-applicatioin
title: 🍋 使用 Fresh 框架构建Web 应用
date: 2023-02-15
authors: kuizuo
tags: [deno, fresh, web, project]
keywords: [deno, fresh, web, project]
description: 使用 Fresh 框架构建Web 应用，用于将链接转换为卡片样式的预览效果图。
---

![](https://img.kuizuo.cn/link-maker.png)

这篇文章将使用 deno 的 web 框架 Fresh，一个简单的 Web 应用 [Link Maker](https://link-maker.deno.dev/ 'Link Maker')，一个用于将链接转换成卡片样式的预览效果。

这个项目也放在了 fresh 的 [Showcase](https://fresh.deno.dev/showcase 'Showcase')，感兴趣的可以查看一番。

<!-- truncate -->

## 什么是 fresh？

[fresh](https://fresh.deno.dev/) 自称是下一代 web 开发框架（这句话怎么这么熟悉?），是一个基于 Deno 的 Web 框架。它提供了许多用于构建 Web 应用程序和 API 的工具和功能。Fresh 框架特别强调简单性和灵活性，并着重于提供最佳的性能和开发体验。它支持 TypeScript，并且不需要任何配置或构建步骤。这些特性使得 Fresh 框架成为构建高效和现代 Web 应用程序的理想选择。

:::caution 声明

Fresh 的前端渲染层由 Preact 完成，包括 Islands 架构的实现也是基于 Preact。如果你想在 Fresh 中使用其他主流前端框架，目前来说有点无能为力。

:::

## 创建 fresh 项目

[Create a project | fresh docs](https://fresh.deno.dev/docs/getting-started/create-a-project 'Create a project | fresh docs')

deno 提供了非常友好的创建 fresh 项目的命令，运行:

```shell
deno run -A -r https://fresh.deno.dev my-project
cd my-project
deno task start
```

根据你的喜好进行配置，如下

![](https://img.kuizuo.cn/image_jSRfPu966v.png)

此时会创建如下文件

```bash
my-project
├── components        # 组件
│   └── Button.tsx    # 按钮组件
├── deno.json         # deno配置文件
├── dev.ts            #
├── fresh.gen.ts      #
├── import_map.json   # 依赖导入映射
├── islands           # 群岛(组件群岛)
│   └── Counter.tsx
├── main.ts           # 入口文件
├── routes            # 路由
│   ├── [name].tsx
│   ├── api
│   │   └── joke.ts
│   └── index.tsx
├── static            # 静态资源
│   ├── favicon.ico
│   └── logo.svg
└── twind.config.ts   # twind配置文件
```

介绍几个文件：

- **`dev.ts`**: 项目开发模式的匹配文件，假设你需要区分生产环境和开发环境，就可以通过 dev.ts，prod.ts 命令来指明入口
- **`main.ts`**: 入口文件，会用于链接 [Deno Deploy](https://deno.com/deploy)。
- **`fresh.gen.ts`**: 这个清单文件会基于`routes/` 和 `islands/` 文件夹自动生成。包含项目的 route 和 island 信息。
- **`import_map.json`**: 这是用于管理项目的依赖项的导入映射。这允许轻松地导入和更新依赖项。

其中最主要的两个目录，这里会细说。

### routes

**`routes/`**: 存放项目中的所有路由。文件即路由，每个文件的名称对应于访问该页的路径。注：此文件夹中的代码永远不会直接发送到客户端.

其中 routes/api 通常存放一些 api 接口，这这里你完全可以将其当做一个 deno 的服务端，可以做后端能做的事情，通常来说就是提供一个可请求的 api 接口。

而其他文件就相当于一个可访问的页面组件，同样是文件路由系统，也可以在这里进行 SSR、中间件操作。

### islands

**`Islands/`**: 群岛，Fresh中我并未看到对这一词的解释，你可以到 [astro 群岛](https://docs.astro.build/zh-cn/concepts/islands/) 看看新的 Web 架构模式，主要作用就是用于存放交互式组件（服务端组件），可以在客户端和服务端运行。有点类似与 next.js 的服务端组件，同样有两种状态（服务端，浏览器端）。

这一部分会有点难理解，你只要知道 IsLands 存放的组件有两种状态（服务端，浏览器端），下文称服务端组件，不同于 components 下的组件，服务端组件有一些优势，例如说

- 可以直接访问服务端相关资源
- 避免了不必要的客户端和服务端之间的交互，因此性能更快
- 允许一些类库可以直接运行在服务端，因此减小了客户端包文件的大小

**想要真正理解服务端组件，就不得不将其与 SSR 拿来对比了。**

SSR 通常是将数据通过服务端的前端框架渲染成 HTML，直接将 HTML 返回给客户端就可以省去 xhr/fetch 请求的过程，只需要首次请求就能得到数据。此时页面交互，数据更新与传统的前端应用没有任何区别，**通俗点说 SSR 就是省去 xhr/fetch 请求的过程**。

而服务端组件会在服务端完成渲染，然后通过自定义的协议发送到客户端。前端应用会将新的 UI 整体（服务端组件）的合并到客户端 UI 树里面（也有叫 hydration 水合），此过程不会对客户端其他状态产生影响，还能达到保持客户端状态的目的，极大的增强了用户体验。

如果你仔细查看控制面板的网络请求输出，可以看到服务器端组件是可以请求的。（这里用的后面实战的截图作为展示）

![](https://img.kuizuo.cn/image_v73eXB47yI.png)

不过既然服务端组件也有很多限制，就比如说服务端状态下，是无法使用 Web 相关 Api 的，数据传输（通过 props）是有前提的，要 JSON 可序列化，也就是说只能传递基本类型、基本对象、数组，像 Date，自定义类，函数等复制对象是无法传递的。

## 实战

项目还是相对比较简单的，将链接转化为一个卡片样式的预览效果（包含链接的标题，图片，描述）。

核心代码在 [`routes\api\link.ts`](https://github.com/kuizuo/link-maker/blob/main/routes/api/link.ts) 下，将会生成 `/api/link` 接口，例如访问 [https://link-maker.deno.dev/api/link?q=https://kuizuo.cn](https://link-maker.deno.dev/api/link?q=https://kuizuo.cn 'https://link-maker.deno.dev/api/link?q=https://kuizuo.cn') 你就可以得到如下 json 数据

```json
{
  "title": "愧怍的小站",
  "description": "Blog",
  "image": "https://kuizuo.cn/img/logo.png",
  "url": "https://kuizuo.cn"
}
```

原理就是通过 fetch 请求目标 url，通常来说得到的是一个 html 页面，这时使用 [deno-dom](https://deno.land/x/deno_dom@v0.1.36-alpha/deno-dom-wasm.ts 'deno-dom') 解析成 Dom 对象，通过 css 选择器选取所要的数据，并整合返回给调用方。

有了这个接口，剩下的前端工作就相对比较轻松了，主要也就是细节话的问题。

## 坑点/不足

下面我会说说,在我编写该应用的时候，有哪些开发体验上的不足之处，如果你恰好有使用 Fresh 框架编写 Web 应用的话，最好需要注意下。

### vscode 下对 deno 项目重构并不友好

当我移动项目 .ts/.tsx 文件的时候，vscode 会将该文件与其他引用该文件的路径更改为 .js/.jsx，这就比较蛋疼了，所以每当要移动文件的时候都要尤为小心。

还有就是文件的依赖关系不是那么准确，尤其是在首次进入项目工程的时候，比如说在 routes/test.tsx 中 导入了 `components/Button.tsx` 组件，当你在 tsx 中写了`<Button></Button>` ，vscode 并不会有任何的引入提示，当你打开 `components/Button.tsx` 文件后就又有了，搞得我都怀疑是不是没有该组件。

### 无法直接通过上下文获取 query 参数

fresh 的 handler 提供两个参数，一般来都会写成下面这种形式，可以区分 Get，Post 请求

```typescript
export const handler = {
  async GET(req: Request, ctx: HandlerContext): Promise<Response> {},
  async POST(req: Request, ctx: HandlerContext): Promise<Response> {},
};
```

假设当前的请求是 /api/test?q=123，我想要获取 query 参数的 q，我得这么做

```typescript
const url = new URL(req.url);
const q = url.searchParams.get('q');
```

当时我尝试用 ctx.query 和 req.query 来获取 q 参数，然而 ctx 与 req 并没有 query 属性，在翻阅文档与源码，才得知 fresh 并没有将 query 参数解析到 req 或 ctx 下。

至于说为何要用 query 而不是用 param，主要是因为 url 的缘故，比如说 `/api/link/https://kuizuo.cn` 这个链接，这时 param 是解析不出 `https://kuizuo.cn` 完整 url 的，除非url编码，但这对使用者来说就不是很好，于是就舍弃了 param 参数的方案。

### 有些 npm 包在 fresh 无法正常使用

在这个应用中我所使用到了 [html2canvas](https://www.npmjs.com/package/html2canvas 'html2canvas') 库用于将页面的 div 元素转成 canvas，以便转成图片的形式并下载。然后在我导入的时候，要么提示找不到该包（大概率是因为 Commonjs），要么就是 html2canvas 不存在，最终无奈我只好将 html2canvas.min.js 存放在 static 下，并在页面中通过 `<script src="/js/html2canvas.min.js"></script>` 方式导入，这样全局有了 html2canvas 就可使用。

### islands 下的组件要时刻注意 Web Api 调用

我在 islands 下的组件中用到了 localStorage 用于持久化数据，然而在我尝试部署到服务器上的时候发现网站无法访问，并在错误日志中提示 localStorage is not defined。

其实这在很多 hydration 框架中都有这一个问题，在 islands 下的组件有两种状态（浏览器端，服务端），后文就称为客户端组件和服务端组件。也正是如此，服务端组件是没有客户端的运行时环境，就比如说你想要在组件中使用 localStorage 对象用来持久化数据，在两种状态下，首先会在服务端执行一遍，然而服务端并没有 localStorage 对象，此时就会提示 localStorage is not defined。

通常的做法是判断组件当前的状态，可以用如下方式来判断是否为浏览器环境。

```typescript
import {IS_BROWSER} from '$fresh/runtime.ts';
```

然后将 localStorage等 Web 相关 API 的调用放在 IS_BROWSER 的判断中。


有篇相关文件非常值得阅读，或许对组件的 hydration 有更好的理解

[💧 Hydration and Server-side Rendering – somewhat abstract](https://blog.somewhatabstract.com/2020/03/16/hydration-and-server-side-rendering/ '💧 Hydration and Server-side Rendering – somewhat abstract')

## 前端框架比较局限

在前面也说过，Fresh 的前端渲染层由 Preact 完成。如果用户要用 React/Vue 那为何不选择生态更好的 next.js/nuxt.js 呢？所以目前来看，Fresh 还是有些无能为力。但可以肯定的是，fresh 的方向与 next.js/nuxt.js 的一致。

## 部署

[deno Deploy](https://dash.deno.com/ 'deno Deploy') 可以非常轻松的部署 fresh 应用，使用 Github 账号登录后，[New Project](https://dash.deno.com/new 'New Project')，从 github 仓库中拉取项目点击 Link 即可部署完毕。

![](https://img.kuizuo.cn/image_CYOAgv6IGe.png)

这里的项目名为 link-maker，那么就会生成 专属访问链接 [https://link-maker.deno.dev](https://link-maker.deno.dev/ 'https://link-maker.deno.dev')（也许要梯子才能访问）

## 结语

最后，在我编写完该应用后，我对其做一个评价吧。收回一开始的一句话，~~fresh 自称是下一代 web 开发框架~~。

如果要让我在 next.js 和 fresh 两个相似的产品中做个选择的话，我肯定毫不犹豫的选择 next.js。一个以一己之力推动了前端的发展，到至今已有越来越多的项目使用 next.js ，我想作为任何一个前端学习者肯定会毫不犹豫的选择 next.js 去编写 web 应用。

就从用户的开发体验而言，就已经很难让我再次选择 fresh，更何况还有像 next.js/nuxt.js 这样的全栈框架。作为一个开发体验（Developer experience）优先的程序员角度来看，如果一个框架想要让别人广泛使用，一定要满足其开发过程，只有沉浸于此，才能不断思考，编写出高质量代码。即便无负担的配置，高性能编译，轻便的部署，这些在他人看来可选择的点（也是 fresh 的点），在我看来却显得很微不足道。

而为什么我会选择尝试 fresh，其实也就想看看能不能找到一个令我眼前一亮的一个全栈 Web 框架，然而目前来看，fresh 还有很长一段距离。
