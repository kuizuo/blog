---
title: 去除ts代码的类型
date: 2022-03-24
authors: kuizuo
tags: [js, ts]
---

在**短时间**内有一个需求，原项目代码是 js，而我手里头的项目是 ts 的，需要将其合并。

按照以往，我通常会将 js 改写成 ts，但时间方面有限，**只希望编译成 js 代码的时候把 ts 中的类型直接删除即可**（最终目的，也就是标题所表明的意思），所以就准备深入了解 TypeScript 的编译配置，也顺带复习一下 tsconfig.json 的相关参数。

**毕竟会写代码，不会编译可就...**

<!-- truncate -->

## 安装 TypeScript

要编写 ts 代码，肯定要先安装其工具

```sh
npm i -g typescript ts-node
```

其中`typescript`自带的 tsc 命令并不能直接运行 typescript 代码，而`ts-node`可以直接运行 ts 代码的能力，省去编译阶段。

但不代表`ts-node`等于 ts 版的 Node.js，本质上 Node.js 只是 JavaScript 的运行时环境，而 Deno 确实可以直接运行 TypeScript。

不过本次的主题不在 ts-node 与 deno，而在于将 TypeScript 代码编译到 JavaScript 代码。

## 简单测试

安装完毕，编写一个`demo.ts`的文件，在里面编写如下代码

```typescript title="demo.ts"
const add = (a: number, b: number): number => {
  return a + b
}

let c = add(1, 2)
```

使用命令 `tsc demo.ts`，将会在同级目录下生成`demo.js`，内容如下（默认是 ES5 标准）

```javascript title="demo.js"
var add = function (a, b) {
  return a + b
}
var c = add(1, 2)
```

## tsconfig.json

可以发现上面转化的代码是 ES5 标准的，然而现在都已经步入到 ES6 阶段了，同时如果有大量 ts 文件需要编译，将十分繁琐，所以就有了 tsconfig.json 用于描述将 **TypeScript** 转为 **JavaScript** 代码的配置文件。

终端使用`tsc --init`，会在目录下生成 tsconfig.json 文件，默认配置如下（已删除原注释）。

```json title="tsconfig.json"
{
  "compilerOptions": {
    "target": "es5", // 编译
    "module": "commonjs", // 模块导入与导出
    "esModuleInterop": true, // 支持合成模块的默认导入
    "forceConsistentCasingInFileNames": true, // 看不懂
    "strict": true, // 严格模式
    "skipLibCheck": true // 跳过.d.ts
  }
}
```

假设我要编译 ES6 语法的，只需要将 es5 改为 es6，然后在终端输入`tsc`，生成的 js 代码就是 es6 规范的代码。

:::info

如果想要单纯的取出 ts 的类型，可以设置`"target": "ESNext"`，除了 ts 的一些特殊标准，如 enum，那么生成的 js 代码基本就是原 ts 代码移除类型的代码。（基本上就已经满足了我一开始的需求）

:::

更多配置 => [TypeScript: TSConfig Reference - Docs on every TSConfig option (typescriptlang.org)](https://www.typescriptlang.org/tsconfig)

这里有份 [tsconfig.json 全解析](https://juejin.cn/post/7039583726375796749#heading-22) 内容如下

```json title="tsconfig.json"
{
  "compilerOptions": {
    /* 基本选项 */
    "target": "es6", // 指定 ECMAScript 目标版本: 'ES3' (default), 'ES5', 'ES2015', 'ES2016', 'ES2017', or 'ESNEXT'
    "module": "commonjs", // 指定使用模块: 'commonjs', 'amd', 'system', 'umd' or 'es2015'
    "lib": [], // 指定要包含在编译中的库文件
    "allowJs": true, // 允许编译 javascript 文件
    "checkJs": true, // 报告 javascript 文件中的错误
    "jsx": "preserve", // 指定 jsx 代码的生成: 'preserve', 'react-native', or 'react'
    "declaration": true, // 生成相应的 '.d.ts' 文件
    "declarationDir": "./dist/types", // 生成的 '.d.ts' 文件保存文件夹
    "sourceMap": true, // 生成相应的 '.map' 文件
    "outFile": "./", // 将输出文件合并为一个文件
    "outDir": "./dist", // 指定输出目录
    "rootDir": "./", // 用来控制输出目录结构 --outDir.
    "removeComments": true, // 删除编译后的所有的注释
    "noEmit": true, // 不生成输出文件
    "importHelpers": true, // 从 tslib 导入辅助工具函数
    "isolatedModules": true, // 将每个文件做为单独的模块 （与 'ts.transpileModule' 类似）.

    /* 严格的类型检查选项 */
    "strict": true, // 启用所有严格类型检查选项
    "noImplicitAny": true, // 在表达式和声明上有隐含的 any类型时报错
    "strictNullChecks": true, // 启用严格的 null 检查
    "noImplicitThis": true, // 当 this 表达式值为 any 类型的时候，生成一个错误
    "alwaysStrict": true, // 以严格模式检查每个模块，并在每个文件里加入 'use strict'

    /* 额外的检查 */
    "noUnusedLocals": true, // 有未使用的变量时，抛出错误
    "noUnusedParameters": true, // 有未使用的参数时，抛出错误
    "noImplicitReturns": true, // 并不是所有函数里的代码都有返回值时，抛出错误
    "noFallthroughCasesInSwitch": true, // 报告switch语句的fallthrough错误。（即，不允许switch的case语句贯穿）

    /* 模块解析选项 */
    "moduleResolution": "node", // 选择模块解析策略： 'node' (Node.js) or 'classic' (TypeScript pre-1.6)
    "baseUrl": "./", // 用于解析非相对模块名称的基础目录
    "paths": {}, // 模块名到基于 baseUrl 的路径映射的列表
    "rootDirs": [], // 根文件夹列表，其组合内容表示项目运行时的结构内容
    "typeRoots": [], // 包含类型声明的文件列表
    "types": [], // 需要包含的类型声明文件名列表
    "allowSyntheticDefaultImports": true, // 允许从没有设置默认导出的模块中默认导入。
    "esModuleInterop": true, // 支持合成模块的默认导入

    /* Source Map Options */
    "sourceRoot": "./", // 指定调试器应该找到 TypeScript 文件而不是源文件的位置
    "mapRoot": "./", // 指定调试器应该找到映射文件而不是生成文件的位置
    "inlineSourceMap": true, // 生成单个 soucemaps 文件，而不是将 sourcemaps 生成不同的文件
    "inlineSources": true, // 将代码与 sourcemaps 生成到一个文件中，要求同时设置了 --inlineSourceMap 或 --sourceMap 属性

    /* 其他选项 */
    "experimentalDecorators": true, // 启用装饰器
    "emitDecoratorMetadata": true // 为装饰器提供元数据的支持
  },
  /* 指定编译文件或排除指定编译文件 */
  "include": ["src/**/*"],
  "exclude": ["node_modules", "**/*.spec.ts"],
  "files": ["index.ts", "test.ts"],
  // 从另一个配置文件里继承配置
  "extends": "@tsconfig/recommended",
  // 让 IDE 在保存文件的时候根据 tsconfig.json 重新生成文件
  "compileOnSave": true // 支持这个特性需要Visual Studio 2015， TypeScript 1.8.4 以上并且安装 atom-typescript 插件
}
```

## 常用配置

原本想自己总结一遍，但刷到了下面这篇文章，总结的太好了，以至于我都不是很想再写一遍主要的配置 🤩

[会写 TypeScript 但你真的会 TS 编译配置吗？ - 掘金 (juejin.cn)](https://juejin.cn/post/7039583726375796749#heading-4)
