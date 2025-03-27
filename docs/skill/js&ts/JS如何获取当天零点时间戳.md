---
id: how-does-js-get-today-zero-timestamp
slug: /how-does-js-get-today-zero-timestamp
title: JS如何获取当天零点时间戳
date: 2021-08-18
authors: kuizuo
tags: [javascript]
keywords: [javascript]
---

<!-- truncate -->

## 需求

准备做一个签到系统，所以当天的 0 点就成为了判断是否签到过的关键点，那 Js 又如何获取对应的时间戳呢？

## 实现

我一开始是这么实现的，利用到的 js 时间库，moment 或者 dayjs 都行，这里选择 dayjs（因为轻量）。

代码如下

```js
dayjs(dayjs().format('YYYY-MM-DD')).valueOf()
```

moment 的话，只需要将 dayjs 替换成 moment 即可。

中间部分取出来的时间为 `“2021-08-18”`，然后再通过 dayjs 转为 Dayjs 对象，并通过 valueOf()，就可获取到当天的零点的时间戳。

思路很明确，就是要先获取到当前日期，然后通过日期在转为时间戳即可

对应的原生 Js 代码也就很明显了

```js
new Date(new Date().toLocaleDateString()).getTime()
```

但要我选择我依旧毫不犹豫选择使用 js 时间库，一些复杂的时间计算，如时间格式化，计算两者时间秒/天数差，给指定时间增加/减少天数，这些如果使用原生 Js 代码，不如直接使用已有的库，何必造个轮子呢。

有关 dayjs 的具体使用就不做介绍了，贴个官方文档，要用的时候查阅一下便可。

[Day.js · 中文文档 - 2kB 大小的 JavaScript 时间日期库](https://day.js.org/zh-CN/)
