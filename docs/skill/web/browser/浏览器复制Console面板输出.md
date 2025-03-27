---
id: brower-copy-console-panel-output
slug: /brower-copy-console-panel-output
title: 浏览器复制Console面板输出
date: 2021-12-07
authors: kuizuo
tags: [javascript, browser, console]
keywords: [javascript, browser, console]
---

<!-- truncate -->

在分析一个网站的时候，要将控制台（Console 面板）中的大数组（长度大约 100）复制到本地上进行调用

```javascript
// 模拟生成的数据
let data = Array.from({ length: 100 }, (v, i) => ({ index: i, value: Math.random() }))
```

![image-20211207122529224](https://img.kuizuo.cn/image-20211207122529224.png)

如果直接鼠标选中复制，是得不到想要的结果的。而我之前的做法都是使用 JSON.stringify() 将其转为 json 文本格式，然后复制到剪贴板

![image-20211207124755461](https://img.kuizuo.cn/image-20211207124755461.png)

很明显 这种方法缺陷很大，首先复制出的结果是一个 JSON 格式数据，其次万一数据很长，复制也很费力，也需要按 Ctrl + C 与 Ctrl + V。无意间刷到个浏览器 API，有个用于复制 js 数据方法----`copy`，使用也特别简单

```
copy(data)
```

此时剪贴板的内容便是 data 的原生 js 对象（格式化后），像下面这样

```javascript
;[
  {
    index: 0,
    value: 0.3875488580101616,
  },
  {
    index: 1,
    value: 0.8932296395340085,
  },
  {
    index: 2,
    value: 0.14681203758288164,
  },
  {
    index: 3,
    value: 0.374650909955935,
  },
  // ...
  {
    index: 99,
    value: 0.31823645771583875,
  },
]
```
