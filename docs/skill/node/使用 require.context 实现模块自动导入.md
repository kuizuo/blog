---
id: use-require.context-to-auto-import-modules
slug: /use-require.context-to-auto-import-modules
title: 使用 require.context 实现模块自动导入
date: 2021-09-12
authors: kuizuo
tags: [node, webpack]
keywords: [node, webpack]
---

<!-- truncate -->

## 前言

在写资源导航的时候，我在将资源分类为一个文件的时候，发现如果我每定义一个分类，那我就需要创建一个文件，然后又要通过`import form`导入，就很烦躁。

![image-20210912080353288](https://img.kuizuo.cn/image-20210912080353288.png)

突然想到貌似 vue-element-admin 中的路由好像也是这样的，而 store 貌似定义完就无需再次导入，于是就开始研究代码，果不其然，发现了`require.context`

![image-20210912080429237](https://img.kuizuo.cn/image-20210912080429237.png)

[依赖管理 | webpack 中文文档 (docschina.org)](https://webpack.docschina.org/guides/dependency-management/)

## 实现

require.context：是一个 webpack 提供的 api,通过执行 require.context 函数遍历获取到指定文件夹（及其下子文件夹）内的指定文件，然后自动导入。

语法：`require.context(directory, useSubdirectories = false, regExp = /^.//)`

- directory 指定文件
- useSubdirectories 是否遍历目录的子目录
- regExp 匹配文件的正则表达式，即文件类型

而上图代码中对应的代码也明确表达要指定`./modules`目录下的，所有 js 文件

```js
const modulesFiles = require.context('./modules', true, /\.js$/)
```

输出一下看看 modulesFiles 到底是什么(console.dir 输出)

![image-20210912081146031](https://img.kuizuo.cn/image-20210912081146031.png)

返回一个函数，但该函数包含三个属性 resolve()、keys()、id

其中`modulesFiles.keys()`则是指定目录下文件名数组

```
 ['./app.js', './permission.js','./settings.js', './tagsView.js', './user.js']
```

接着看下 vue-element-admin 中的下一行代码

```js
const modules = modulesFiles.keys().reduce((modules, modulePath) => {
  // set './app.js' => 'app'
  const moduleName = modulePath.replace(/^\.\/(.*)\.\w+$/, '$1')
  const value = modulesFiles(modulePath)
  modules[moduleName] = value.default
  return modules
}, {})
```

这边先输出一下 modules，看下结果是什么

![image-20210912081553729](https://img.kuizuo.cn/image-20210912081553729.png)

没错，正对应着 modules 下的所有文件，以及所导出的对象

其中在循环体中还调用了`const value = modulesFiles(modulePath)`，其中 value 是 Module 对象，有个属性`default`，通过`value.default`便可获取到对应模块所导出的内容。

就此便可以实现自动导入模块。不过由于导出的是 store 对象，所封装的代码也有点过于复杂，这边我贴下我是如何自动导入数组对象的

```typescript
const modulesFiles = require.context('./modules', true, /\.ts$/)

let allData: any[] = []

modulesFiles.keys().forEach((modulePath) => {
  const value = modulesFiles(modulePath)
  let data = value.default

  if (!data) return
  allData.push(...value.default)
})
```

## 参考链接

> [前端优化之 -- 使用 require.context 让项目实现路由自动导入 - 沐浴点阳光 - 博客园 (cnblogs.com)](https://www.cnblogs.com/garfieldzhong/p/12585280.html)
