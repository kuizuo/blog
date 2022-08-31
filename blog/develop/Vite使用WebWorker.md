---
slug: vite-webworker
title: Vite使用WebWorker
date: 2022-07-26
authors: kuizuo
tags: [vite, webworker]
keywords: [vite, webworker]
---

准备给我的一个 Vite 项目进行重构，其中一个功能(函数)要花费 JS 主线程大量时间，会导致主线程画面卡死，无法正常点击，直到该功能(函数)执行完毕而言。这样的用户体验非常差，于是就准备使用 WebWorker 对该功能封装。

<!-- truncate -->

## WebWorker 限制

（1）**同源限制**

分配给 Worker 线程运行的脚本文件，必须与主线程的脚本文件同源。

（2）**DOM 限制**

Worker 线程所在的全局对象，与主线程不一样，无法读取主线程所在网页的 DOM 对象，也无法使用`document`、`window`、`parent`这些对象。但是，Worker 线程可以`navigator`对象和`location`对象。

（3）**通信联系**

Worker 线程和主线程不在同一个上下文环境，它们不能直接通信，必须通过消息完成。

（4）**脚本限制**

Worker 线程不能执行`alert()`方法和`confirm()`方法，但可以使用 XMLHttpRequest 对象发出 AJAX 请求。

（5）**文件限制**

Worker 线程无法读取本地文件，即不能打开本机的文件系统（`file://`），它所加载的脚本，必须来自网络。

综合以上限制，我所要重构的功能面临以下问题

- 一些 window 下的函数，或者主线程下全局数据函数，无法共同
- 无法读取本地文件，需要创建网络文件（如 Blob 或 Vite 导入）
- Worker 线程和主线程通信要使用`worker.postMessage`与`self.addEventListener`来发送与监听数据。

**所以在考虑使用 Worker 的时候就要考虑这个功能是否值得使用 Worker，能否使用 Worker 实现**

## Vite 中使用 WebWorker

这里先给出我的最优解，在 Vite 中[静态资源处理 ](https://cn.vitejs.dev/guide/assets.html)，其中可以[导入脚本作为 Worker](https://cn.vitejs.dev/guide/assets.html#importing-script-as-a-worker)

```javascript title="main.js"
import Worker from './test.worker.js?worker'
const worker = new Worker()
```

这个 worker 就是所要的 Worker 对象，接着就可以对象的 postMessage 与 onmessage 来数据通信，如

```javascript title="main.js"
worker.onmessage = (e) => {
  console.log('main.js', e.data)
}

worker.postMessage('hello from main')
```

```javascript title="test.worker.js"
self.addEventListener(
  'message',
  function (e) {
    console.log('test.worker.js', e.data)
    self.postMessage('hello from worker')
  },
  false,
)
```

不过 Vite 还有[其他方式](https://cn.vitejs.dev/guide/features.html#web-workers)导入 Worker

```javascript
const worker = new Worker(new URL('./worker.js', import.meta.url))
```

这种方式相对更加标准，但是如果worker并不是一个js文件，而是ts文件，并且还夹杂一些第三方的包，这种方式是有可能会失败，本人测试是这样的，所以推荐一开始的方式，也就是带有查询后缀的导入。

在打包的时候将其实所用到引入的依赖合并成一个文件，如果打开开发者工具，可以在源代码面板的右侧线程中看到主线程，以及worker线程。

## 参考文章

[使用 Web Workers - Web API 接口参考 | MDN (mozilla.org)](https://developer.mozilla.org/zh-CN/docs/Web/API/Web_Workers_API/Using_web_workers)

[Web Worker 使用教程 - 阮一峰的网络日志 (ruanyifeng.com)](https://www.ruanyifeng.com/blog/2018/07/web-worker.html)
