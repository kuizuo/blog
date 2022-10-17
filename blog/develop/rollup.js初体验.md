---
slug: rollup-js-experience
title: rollup.js 初体验
date: 2022-10-18
authors: kuizuo
tags: [rollup, webpack, utils]
keywords: [rollup, webpack, utils]
---

# rollup.js 初体验

![rollup.js](https://img.kuizuo.cn/rollupjs.png)


近期准备写一个工具包 [@kuizuo/utils](https://github.com/kuizuo/utils "@kuizuo/utils")，由于要将其发布到npm上，必然就要兼容不同模块（例如 CommonJS 和 ESModule），通过打包器可以很轻松的将代码分别编译成这不同模块格式。

恰好 [rollup 3](https://github.com/rollup/rollup/releases/tag/v3.0.0 "rollup 3") 正式发布，也算是来体验一下。

<!-- truncate -->

### 为什么不是Webpack？

`rollup` 的特色是 `ES6` 模块和代码 `Tree-shaking`，这些 `webpack` 同样支持，除此之外 `webpack` 还支持热模块替换、代码分割、静态资源导入等更多功能。

当开发应用时当然优先选择的是 `webpack`，但是若你项目只需要打包出一个简单的 `bundle` 包，并是基于 `ES6` 模块开发的，可以考虑使用 `rollup`。

**`rollup` 相比 `webpack`，它更少的功能和更简单的 api，是我们在打包类库时选择它的原因。**例如本次要编写的工具包就是这类项目。

## 支持打包的模块格式

目前常见的模块规范有：&#x20;

- IFFE：使用立即执行函数实现模块化 例：`(function(){})()`

- CJS：基于 CommonJS 标准的模块化

- AMD：使用 Require 编写

- ESM：ES 标准的模块化方案 ( ES6 标准提出 )

- UMD：兼容 CJS 与 AMD、IFFE 规范

以上 Rollup 都是支持的。

## 使用

官方有一篇文章 [创建你的第一个bundle](https://rollupjs.org/guide/en/#creating-your-first-bundle "创建你的第一个bundle") ，不过英文文档比较难啃，同时通过命令方式+选项的方式来打包肯定不是工程化想要的。

### 配置文件

所以这里所演示的是通过 `rollup.config.js` 文件，通过`rollup -c` 来打包。

一个示例文件如下

```javascript title='rollup.config.js'
export default {
  input: 'src/main.js',
  output: {
    file: 'bundle.js',
    format: 'cjs'
  }
};
```

执行 `rollup -c` 就会将`main.js` 中所引用到的js代码，通过`commonjs`的方式编写到`bundle.js`，就像这样。

```javascript title='bundle.js'
'use strict';

var foo = 'hello world!';

function main () {
  console.log(foo);
}

module.exports = main;

```

但是更多的情况下，是需要同时打包多个模块格式的包，就可以在output传入数组，例如

```javascript title='rollup.config.js'
export default {
  input: 'src/main.js',
  output: [{
    file: 'bundle.cjs',
    format: 'cjs'
  }, {
    file: 'bundle.mjs',
    format: 'esm'
  }]
};
```

便会生成 `bundle.cjs`, `bundle.mjs` 两种不同的模块格式的文件。同时在 `package.json` 中，指定对应模块路径，在引入时，便会根据当前的项目环境去选择导入哪个模块。

```javascript title='package.json'
{
  "main": "bundle.cjs",
  "module": "bundle.mjs"
}
```

### 结合rollup插件使用

不过更多情况下，rollup需要配置插件来使用。官方插件地址：[rollup/plugins: 🍣 The one-stop shop for official Rollup plugins (github.com)](https://github.com/rollup/plugins "rollup/plugins: 🍣 The one-stop shop for official Rollup plugins (github.com)")

比如使用 [rollup-plugin-esbuild](https://github.com/egoist/rollup-plugin-esbuild "rollup-plugin-esbuild") 插件来使用[esbuild](https://esbuild.docschina.org/ "esbuild")（也是一个打包器，并且构建非常快）来加快打包速度。可以使用 [@rollup/plugin-babel](https://github.com/rollup/plugins/tree/master/packages/babel "@rollup/plugin-babel") 借助babel，编译成兼容性更强的js代码或者代码转换等等。

以下是rollup+插件的配置示例，来源 [antfu/utils/rollup.config.js](https://github.com/antfu/utils/blob/main/rollup.config.js "antfu/utils/rollup.config.js") ，也作为本次工具包的配置。

```javascript title='rollup.config.js'
import esbuild from 'rollup-plugin-esbuild'
import dts from 'rollup-plugin-dts'
import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'
import alias from '@rollup/plugin-alias'

const entries = [
  'src/index.ts',
]

const plugins = [
  alias({
    entries: [
      { find: /^node:(.+)$/, replacement: '$1' },
    ],
  }),
  resolve({
    preferBuiltins: true,
  }),
  json(),
  commonjs(),
  esbuild({
    target: 'node14',
  }),
]

export default [
  ...entries.map(input => ({
    input,
    output: [
      {
        file: input.replace('src/', 'dist/').replace('.ts', '.mjs'),
        format: 'esm',
      },
      {
        file: input.replace('src/', 'dist/').replace('.ts', '.cjs'),
        format: 'cjs',
      },
    ],
    external: [],
    plugins,
  })),
  ...entries.map(input => ({
    input,
    output: {
      file: input.replace('src/', '').replace('.ts', '.d.ts'),
      format: 'esm',
    },
    external: [],
    plugins: [
      dts({ respectExternal: true }),
    ],
  })),
]

```

以下是对应的npm 安装命令

```bash
pnpm i -D rollup @rollup/plugin-alias @rollup/plugin-commonjs @rollup/plugin-json @rollup/plugin-node-resolve rollup-plugin-esbuild rollup-plugin-dts
```

关于rollup更多使用，不妨参见 [rollup官方文档](https://rollupjs.org/ "rollup官方文档")，以及一些使用 rollup 来打包的开源项目。

## 类似工具

类似的工具还有 [webpack.js](https://webpack.js.org/ "webpack.js"), [esbuild](https://esbuild.github.io/ "esbuild"), [parceljs](https://parceljs.org/ "parceljs")

不过就打包类库而言，并不要求过强的性能，有个相对简单的配置就足以，而 [rollup](https://rollupjs.org/ "rollup") 正是这样的打包工具。

## 相关文章

[【实战篇】最详细的Rollup打包项目教程](https://juejin.cn/post/7145090564801691684 "【实战篇】最详细的Rollup打包项目教程")

[一文带你快速上手Rollup](https://zhuanlan.zhihu.com/p/221968604 "一文带你快速上手Rollup")