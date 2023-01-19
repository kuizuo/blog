---
slug: deno-is-not-only-a-javascript-runtime
title: Deno不只是个Javascript运行时
date: 2023-01-20
authors: kuizuo
tags: [deno, node, javascript, typescript]
keywords: [deno, node, javascript, typescript]
---

<img src="https://deno.land/logo.svg" width="150" height="150" />

Deno 是一个安全的 JavaScript 和 TypeScript 运行时，作者是 Ryan Dahl（也是 Node.js 的原作者）。Deno 的诞生之初是为了[解决 2009 年首次设计 Node.js 时的一些疏忽](https://link.juejin.cn?target=https://www.youtube.com/watch?v=M3BM9TB-8yA)。我认为这种改造动机很有道理，因为**我相信每个程序员都希望有机会能重写他们已有 10 年历史的代码。**

deno 刚出的时候就听闻了，传言 deno 是下一代 node.js。不过如今看来，还革不了 node.js 的命。如果要说两者字面上的区别，Deno 的来源是 Node 的字母重新组合（Node = no + de），表示"拆除 Node.js"（de = destroy, no = Node.js）。

趁着假期学了一段时间的 deno（指[文档](https://deno.land/manual@v1.29.3/introduction '文档')刷了一遍），想分享本人作为 node 开发者在学习 deno 时认为的一些亮点，以及个人对 deno 与 node 见解。

<!-- truncate -->

### 开发环境

[Installation | Manual | Deno](https://deno.land/manual@v1.29.2/getting_started/installation 'Installation | Manual | Deno')

默认情况下 deno 会根据不同的系统，选择相应的安装目录，以及依赖目录，你可以[配置环境变量](https://deno.land/manual@v1.29.3/getting_started/setup_your_environment#environment-variables '配置环境变量')来改变 deno 的默认行为。

这里我选用 vscode 进行开发，安装[deno 官方插件](https://marketplace.visualstudio.com/items?itemName=denoland.vscode-deno 'deno官方插件')。此时创建一个项目工程文件夹，打开 vscode，并创建 `.vscode/settings.json` 内容如下

```json title='.vscode/settings.json'
{
  "deno.enable": true,
  "deno.lint": true,
  "editor.formatOnSave": true,
  "[typescript]": {"editor.defaultFormatter": "denoland.vscode-deno"}
}
```

在 vscode 中默认会将 ts 代码认为是 node 运行时环境，因此需要在项目工程下手动配置并启用 deno，让 vscode 以 deno 运行时环境来语法解析 ts 代码。

## deno 的一些亮点💡

因为 deno 与 node 一样，都是 javascript 运行时（deno 合理来说是 typescript 运行时）。所以在 javascript 的部分就没什么好说的了，主要对比 deno 相比与 node 的优势，或说我个人觉得一些使用亮点。

### 官方所介绍的亮点

以下是官方所介绍的[亮点](https://deno.land/manual@v1.29.3/introduction#feature-highlights '亮点')，我对其做了翻译

- 提供[web 平台功能](https://deno.land/manual@v1.29.3/runtime/web_platform_apis 'web平台功能')，采用网络平台标准。例如，使用 ES 模块、Web worker 和支持 `fetch()`。
- 默认安全。除非显式启用，否则无法访问文件、网络或环境。

- 支持开箱即用的 [TypeScript](https://deno.land/manual@v1.29.3/advanced/typescript 'TypeScript')。
- 提供单个可执行文件 （`deno`）。
- 为编辑器提供内置的开发工具，如代码格式化程序 （[deno fmt](https://deno.land/manual@v1.29.3/tools/formatter 'deno fmt')）、linter （[deno lint](https://deno.land/manual@v1.29.3/tools/linter 'deno lint')）、测试运行程序（[deno test](https://deno.land/manual@v1.29.3/basics/testing 'deno test')）和[语言服务器](https://deno.land/manual@v1.29.3/getting_started/setup_your_environment.md#using-an-editoride '语言服务器')。
- 拥有[一组经过审查（审核）的标准模块](https://deno.land/std@0.172.0 '一组经过审查（审核）的标准模块')，保证与 Deno 一起使用。
- 可以将脚本[捆绑](https://deno.land/manual@v1.29.3/tools/bundler '捆绑')到单个 JavaScript 文件或[可执行文件](https://deno.land/manual@v1.29.3/tools/compiler '可执行文件')中。
- 支持使用现有的 npm 模块

以下会针对部分亮点，进行个人的见解。

### 自带实用工具

deno 则是自带代码格式化（`deno fmt`）、代码风格（`deno lint`）、代码测试（`deno test`）、依赖检查器（`deno info`）等等的功能。而这些在 node 中，你需要通过第三方的库，如 eslint，jest 才能实现。

你可以在项目工程中添加配置文件 [deno.json](https://deno.land/manual@v1.29.2/getting_started/configuration_file 'deno.json')来定制化代码风格（rust 中也有类似的功能），但在 node 中必须要借助第三方的库，或是 IDE 才能实现。

不过也能理解，在当时的编程环境背景下，javascript 还主要作为前端的脚本语言使用，又怎能让 node 来做相关规范呢？（这句话可能有点不妥）

**这点我认为对开发者是否选用你这门语言的一个加分项**，并且这些功能也应该作为编程语言所自带的，有官方的背书（保证），对代码风格才更有所保障。

这里有份 [官方小抄](https://deno.land/manual@v1.29.4/references/cheatsheet#nodejs---deno-cheatsheet '官方小抄') 可以知道通过`deno xxx`等命令能够做到 node 原本需要通过第三方库才能实现的功能。

| Node.js | Deno |
| --- | --- |
| `node file.js` | `deno run file.js` |
| `ts-node file.ts` | `deno run file.ts` |
| `npm i -g` | `deno install` |
| `npm i` / `npm install` | _n/a_ |
| `npm run` | `deno task` |
| `eslint` | `deno lint` |
| `prettier` | `deno fmt` |
| `rollup` / `webpack` / etc | `deno bundle` |
| `package.json` | `deno.json` / `deno.jsonc` / `import_map.json` |
| `tsc` | `deno check` |
| `typedoc` | `deno doc` |
| `jest` / `ava` / `mocha` / `tap` / etc | `deno test` |
| `nodemon` | `deno run/lint/test --watch` |
| `nexe` / `pkg` | `deno compile` |
| `npm explain` | `deno info` |
| `nvm` / `n` / `fnm` | `deno upgrade` |
| `tsserver` | `deno lsp` |
| `nyc` / `c8` / `istanbul` | `deno coverage` |
| `benchmarks` | `deno bench` |

### [远程导入](https://deno.land/manual@v1.29.3/basics/modules#remote-import '远程导入')

与 node 不同，使用 node 通常需要从 npm 官方包来下载并导，有 npm 这样的包管理器来统一管理这些包（package），我们通常称这种为中心化，而 deno 与 go 的做法很像，你可以将你的封装好的代码定义成一个包，并将其放在任何网络可访问的地方，比如 github，或是私有地址，然后通过网络读取文件的方式来导入，这种称为去中心化。

:::tip

node 也不一定要用 npm 来下载模块，也可以本地模块或者私有模块。

:::

关于中心化与去中心化管理，各有优缺，这里不做细致讨论。

以下是 deno 官方远程导入的代码示例：

**Command: deno run ./remote.ts**

```typescript title='remote.ts'
import {add, multiply} from 'https://x.nest.land/ramda@0.27.0/source/index.js';

function totalCost(outbound: number, inbound: number, tax: number): number {
  return multiply(add(outbound, inbound), tax);
}

console.log(totalCost(19, 31, 1.2));
console.log(totalCost(45, 27, 1.15));

/**
 * Output
 *
 * 60
 * 82.8
 */
```

而这里的 `https://x.nest.land/ramda@0.27.0/source/index.js` 可以替换成任何 ES module 特性（import/export）的模块。

### http 的方式运行代码

既然都能通过 http（cdn）远程导入模块，那远程运行文件自然也不成大问题。有时候像快捷体验一下别人的代码，或是想要在浏览器中运行一下代码，这时候就可以通过 http 的方式来运行代码。

这里我准备了一段代码，并部署到我的站点上，你可以通过如下命令得到该代码的执行结果（如果你有安装 deno 的话），放心这段代码并无危害，就是一段简单的 console.log 输出。

```powershell
deno run https://deno.kuizuo.cn/main.ts
```

在第一次使用时下载并缓存代码，你可以通过

```powershell
deno info http://deno.kuizuo.cn/main.ts
```

来查看文件信息，如下

![](https://img.kuizuo.cn/image_deb0_lGYRA.png)

deno info 还可以查看 deno 的相关配置，默认缓存都设置在 C 盘，你也可以设置**DENO_DIR** 环境变量来更改 deno 目录，可以到 [Set Up Your Environment](https://deno.land/manual@v1.29.3/getting_started/setup_your_environment#environment-variables 'Set Up Your Environment') 查看 deno 相关环境变量。

### 依赖管理

经常使用 node 的开发者应该对 node 的依赖感到无比厌烦，关于这部分强烈建议看 [node_modules 困境](https://juejin.cn/post/6914508615969669127)，你就能知道 node 的 node_modules 设计的是有多少问题。看完你也就能知道为啥越来越多的 node 项目都使用 [pnpm](https://pnpm.io) 作为包管理。

虽然 node 有了 pnpm 包管理器这种情况会好一些，但本质在项目目录还是需要 node_modules 文件。也许你用过其他语言的包管理器，你会发现基本都是将所有用到的依赖全局缓存起来，当不同的项目工程需要用到依赖时，直接去全局缓存中找，而不是像 npm 一样，下载到项目工程目录下，存放在 node_modules 里。

而 deno 也是采用这种这种方式，`no npm install`，`no package.json`，`no node_modules/` ，[使用 npm 包](https://deno.land/manual@v1.29.3/node/npm_specifiers#using-npm-packages-with-npm-specifiers '使用npm包')可以像下面这样，当你使用 deno run 时便会下载好依赖置全局缓存中。

```typescript title="app.ts" {2}
// @deno-types="npm:@types/express@^4.17"
import express from 'npm:express@^4.17';
const app = express();

app.get('/', (req, res) => {
  res.send('Hello World');
});

app.listen(3000);
console.log('listening on http://localhost:3000/');
```

deno 刚发布的时候，甚至还不支持 NPM 软件包，这无非是要告诉用户 deno 社区没有轮子，要求用户自己去造一个。不过 deno 团队还是做出了比较正确的选择，支持 npm 软件包，并且还非常友好。

不过如果你在 deno 中使用了 npm 包，可能会存在一些兼容性问题，万一遇到了，也可以通过添加 `--node-modules-dir` 标识，在当前运行目录下创建 `node_modules` 文件夹。详见 [--node-modules-dir flag](https://deno.land/manual@v1.29.4/node/npm_specifiers#--node-modules-dir-flag '--node-modules-dir flag')

### 安全

[Permissions](https://deno.land/manual@v1.29.4/basics/permissions 'Permissions')

在 2022 年 npm 出现过一些恶性的库，如 lodash-utils, faker.js, chalk-next。万一你不小心安装了上面，轻则项目无法运行，输出无意义乱码，重则删除本地文件。

又因为 npm 几乎没有代码审计的机制，任何开发者只需要有一个 npm 的账号就能在上面随意发布他想发布的包。通常来说电脑病毒都是通过随意读取与写入本地文件来达到病毒的目的，但在 deno 中，代码如果尝试写入与读入文件，都需要询问开发者是否允许操作。并且在 linux 系统，你可以指定像 /usr /etc 这样非 root 角色来操作该文件，避免真是病毒文件导致删除不该删除的文件。

此外像命令执行，网络访问，环境变量这些极易危害电脑的权限，deno 都会检测到，并做出提示告诫开发者是否允许执行。总之你能想到的电脑安全隐患，deno 都为你做好了。

### 内置浏览器环境（运行时）

这是我认为 deno 最大的亮点。

总所周知，浏览器的 js 代码有很大概率是无法直接在 node 中跑起来的，原因就是 node 的全局对象中没有浏览器的对象，如 window，document，甚至连`localStorage` 都有！

这说明什么，往常如果你从别的网站扣了一段代码下来，想在 node 运行会发现什么 window is not defined，xxx is not defined。如果想在 node 运行，你必须需要补齐浏览器的环境，此外可以借助 js-dom，happy-dom 等 npm 包。而 window，xxx 这些全局只有浏览器才定义的全局对象在 deno 的运行时同样定义了，可以到[这里](https://deno.land/manual@v1.29.3/runtime/web_platform_apis#using-web-platform-apis '这里')查看支持的 Web 平台 API。

虽说与真实浏览器全局对象有些许差异，但这也足够让开发者少做很多工作。比如 Web 逆向者通常要扣取浏览器的 js 代码，并补齐环境使其能够在 node 中运行，而有了 deno 这将变得非常轻松！

**与其说是 javascript/typescript 运行时，我更愿意说是浏览器运行时！**

### Web 框架

你可以在 [Web Frameworks](https://deno.land/manual@v1.29.2/getting_started/web_frameworks 'Web Frameworks') 中看到 deno 官方所推荐的 Web 框架，其中 [Fresh](https://deno.land/manual@v1.29.2/getting_started/web_frameworks#fresh 'Fresh') 也是最为推荐使用的（后续我也会尝试使用该框架）。

而在 node 社区中，你会看到像 express，koa，nestjs 等等这种非 Node 官方或大背景的 web 框架（而且还很多），而这时对于初学者而言，就有点不知道该如何做出抉择。

而像 java 中你完全可以不用担心该学什么，说学 spring 就是在学 java 这可一点都不为过。可能这也是国内 java，尤其是 spring 的开发者尤为诸多的原因。

吐槽归吐槽，但我想表明的是在有官方的支持下，用户和开发者能够统一使用某个框架，一起维护与使用一个更好的框架。而不是个个 Web 框架的都有各自的优缺点，让使用者去选择，搞得这个框架是另一个框架的轮子一般。

所以我认为这种支持是很有必要。

### 公共托管服务

[Project - Deploy (deno.com)](https://dash.deno.com/ 'Project - Deploy (deno.com)')

deno 像 vercel/netfily 一样提供了一个代码托管服务，可以将你的 deno 应用部署上去。对，目前来看还无法部署前端应用，因为要指明一个入门文件（main.ts）。

你可以通过 [https://kuizuo.deno.dev/](https://kuizuo.deno.dev/ 'https://kuizuo.deno.dev/') 来访问我使用 deno Deploy 所创建的一个在线项目。将会输出一个`Hello World!` 的页面。

提供一个免费的线上环境体验，对开发者而言尤为重要，尤其是在将自己的项目成果分享给他人展示时，成就感油然而生。

## node 转 deno 开发的一些帮助

deno 相关的亮点我也差不多介绍完了，也许你对 deno 已经有一丝兴趣想尝试一番，以下我整理的对你也许有所帮助。

- 如果你是一个 Node 用户，考虑切换到 Deno，这里有一个[官方小抄](https://link.juejin.cn/?target=https://deno.land/manual/node/cheatsheet '官方小抄')来帮助你。

- 如果你不想刷 deno 文档，想快速上手 deno 的话，这里我建议推荐看看 deno 官方所推荐的[deno 代码例子 ](https://deno.land/manual@v1.29.4/examples 'deno代码例子 ')，能够非常快速有效了直接了解 deno 标准库以及依赖导入导出。

- deno 是集成了 node 与 npm 的，也就是说允许直接使用 npm 包与 node 标准库，如果你想用 deno 来写 node，也行，详看[Interoperating with Node.js and npm](https://deno.land/manual@v1.29.4/node#interoperating-with-nodejs-and-npm 'Interoperating with Node.js and npm')。

- 想要在 deno 中连接数据库，可看[Connecting to Databases](https://deno.land/manual@v1.29.4/basics/connecting_to_databases#connecting-to-databases 'Connecting to Databases')。

- 如果想看 deno 如何使用 deno 生态的 Web 框架创建一个 Web 服务，推荐[fresh](https://fresh.deno.dev/ 'fresh')框架，并查看该例子[fresh/examples/counter](https://github.com/denoland/fresh/tree/main/examples/counter 'fresh/examples/counter')

## node 火吗?

关于 deno 就暂且落下笔墨，不妨思考一个问题，node 火吗。

作为 node 开发者，我肯定会说 node 火，不过更多是对 javascript 来说火。

:::info 2022 State of JS
2022 也结束了，不妨查看 [2022 State of JS](https://2022.stateofjs.com '2022 State of JS') 数据报告统计，看看 JavaScript 在 2022 年是如何发展的吧。
:::

如今 typescript 大势所趋，说 javascript 就等同于说 typescript，而 javascript 和 node 绑定已成事实，而前端也与 javascript 所绑定，如今的前端工程师要是不会 node，都不好意思说自己是个前端工程师。就现阶段看，没了 nodejs，前端技术得倒退十年（不夸张）。

如果是在 Web 前端，Node 确实已经火的一塌糊涂了，然而它的诞生并不是为了 Web 前端，而是希望将 javascript 作为服务器端语言发展。只是后来没有想到的是 Node.js 在前端领域却大放异彩，造就了如今大前端的盛世。

所以在 Web 后端的领域，Node 确实是不温不火，更多的公司都宁可选主流的后端开发语言，而不是优先考虑 Node。不过倒是在 Serverless 领域中，Node 有着一席之地。

所以我想 deno 的出现，不仅是针对 Node.js 的缺陷，更是针对 Node.js 后端开发的不足。至于说 deno 能否完成原先 node 的使命，只有时间能给我们答案。

## 总结

从上述看来，你应该会发现 deno 并不和 node 一样是一个纯运行时环境。因为他不仅仅做了 javascript/typescript 运行时环境，还做了很多开发者好评的功能，一个为 javascript/typescript 提供更好的开发支持的产品。

但好评并不能直接决定销量，这些功能看似可有可无，没有激起用户从 Node.js 切换过来的杰出之处。就我体验完发现，好像 deno 能做的东西 node 大部分也能做，只是相对繁琐重复一些而已。**但人们更倾向于做一件繁琐重复的事情，而不是做一个新的事情。**

扪心自问，我真的很希望 deno 能火，就开发体验而言，比 node 好用太多了，但好用的东西代表不了用的人就多，这个领域中，生态尤为重要。想要让 node 用户转到 deno 开发还有很长一段路要走。

再来反问自己，我现在会将 deno 作为 node 替代品吗，我想我和多数 node 开发者一样，都不会将 deno 作为主力语言(因为有很多项目都已经使用node来进行开发与推动)。但作为个人开发者，尤其是 node 开发者，我认为还是非常有必要去尝试一番 deno，亲手目睹"下一代Node"。

希望本文能对你了解 deno 有所帮助。

## 相关推荐文章

[Deno vs. Node.js 哪个更好 - 掘金 (juejin.cn)](https://juejin.cn/post/7168383367602241550 'Deno vs. Node.js哪个更好 - 掘金 (juejin.cn)')

[为什么 Deno 没有众望所归？超越 Node.js 还要做些什么？ - 掘金 (juejin.cn)](https://juejin.cn/post/6956461134299955213 '为什么 Deno 没有众望所归？超越 Node.js 还要做些什么？ - 掘金 (juejin.cn)')

[连发明人都抛弃 node.js 了，还有前途吗？ - 知乎 (zhihu.com)](https://www.zhihu.com/question/327534747 '连发明人都抛弃node.js了，还有前途吗？ - 知乎 (zhihu.com)')

[已经 2022 年了 Deno 现在怎么样了? - 知乎 (zhihu.com)](https://www.zhihu.com/question/517617266 '已经 2022 年了 Deno 现在怎么样了? - 知乎 (zhihu.com)')
