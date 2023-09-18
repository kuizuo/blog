---
id: commonly-used-util.js
slug: /commonly-used-util.js
title: 常用util.js
date: 2020-10-21
authors: kuizuo
tags: [js, util]
keywords: [js, util]
---

记录一下自己在 js 学习中常用到的一些方法，进行封装使用

<!-- truncate -->

## 1.时间格式解析

首当其冲的就是这个时间格式解析了，js 的 Date 中有一个方法`toLocaleString()` 返回的结果为本地时间，如`new Date().toLocaleString()`返回为`2020/10/21 上午1:03:17`，好像看着并没有什么问题，但是我如果要将`2020/10/21 上午1:03:17`转为时间戳的话，也就是执行`new Date("2020/10/21 上午5:03:17").getTime()`，然而它却返回`NaN`，不合理啊，时间格式难道不是这样的吗，时间格式还真不是这样，上面只是显示为本地的时间，然而对于 js 而言，它只识别`yyyy-MM-dd HH:mm:ss`这样的时间格式。于是就需要对返回的时间格式进行操作了。

可以通过下方的解析函数，并带上对应的时间格式返回给我对应的时间，代码就不分析了，我也是借鉴网络上的一些格式化时间代码，修改而来的。

```js
function parseTime(time, cFormat) {
  if (arguments.length === 0 || !time) {
    return null
  }
  const format = cFormat || '{y}-{m}-{d} {h}:{i}:{s}'
  let date
  if (typeof time === 'object') {
    date = time
  } else {
    if (typeof time === 'string') {
      if (/^[0-9]+$/.test(time)) {
        time = parseInt(time)
      } else {
        time = time.replace(new RegExp(/-/gm), '/')
      }
    }

    if (typeof time === 'number' && time.toString().length === 10) {
      time = time * 1000
    }
    date = new Date(time)
  }
  const formatObj = {
    y: date.getFullYear(),
    m: date.getMonth() + 1,
    d: date.getDate(),
    h: date.getHours(),
    i: date.getMinutes(),
    s: date.getSeconds(),
    a: date.getDay(),
  }
  const time_str = format.replace(/{([ymdhisa])+}/g, (result, key) => {
    const value = formatObj[key]
    if (key === 'a') {
      return ['日', '一', '二', '三', '四', '五', '六'][value]
    }
    return value.toString().padStart(2, '0')
  })
  return time_str
}
```

## 2.计算过去时间距离现在时间差

上面说到的是时间结构的解析，但有时候需要计算过去时间与现在的时间差，比如计算评论发布的时间。这个我也放一个对应的相关代码

```js
function formatTime(time, option) {
  if (('' + time).length === 10) {
    time = parseInt(time) * 1000
  } else {
    time = +time
  }
  const d = new Date(time)
  const now = Date.now()

  const diff = (now - d) / 1000

  if (diff < 30) {
    return '刚刚'
  } else if (diff < 3600) {
    // less 1 hour
    return Math.ceil(diff / 60) + '分钟前'
  } else if (diff < 3600 * 24) {
    return Math.ceil(diff / 3600) + '小时前'
  } else if (diff < 3600 * 24 * 2) {
    return '1天前'
  }
  if (option) {
    return parseTime(time, option)
  } else {
    return d.getFullYear() + '年' + (d.getMonth() + 1) + '月' + d.getDate() + '日' + d.getHours() + '时' + d.getMinutes() + '分'
  }
}
```

这里提一下`moment.js`，一个 js 日期处理的类库，有兴趣的可以去了解一下 [moment.js](http://momentjs.cn/)

## 3.取随机数，字母

js 提供了获取随机数的方法`Math.random()` ，但返回的是一个获取 0-1 之间的随机数，如`0.8790767725487598`，当然，这肯定不是我们想要的，我要的只是一个 0-9 数字，很简单，只需要将上面获取到的随机数乘 10，然后取个位数不就成了。对应的也就是

`parseInt(Math.random() * 10)`

有时候肯定不只是要 0-9 之间，可能是要 0-100 的，原理一样，对应的换算公式如下

获取 N-M 的随机数 `parseInt(Math.random() * (M - N + 1) + N)`

封装成如下对应代码

```js
function ranNum(min, max) {
  if (arguments.length === 0) {
    return parseInt(Math.random() * 10)
  }
  return parseInt(Math.random() * (max - min + 1) + min)
}
```

对应的获取随机字母也简单,只要通过 ASCII 码 A 为 65，Z 为 90，然后获取随机数 0-25，通过`String.fromCharCode`传入对应的 ASCII 码即可，如下

```js
function ranChar() {
  return String.fromCharCode(65 + parseInt(Math.random() * 25))
}
```

## 4.查询字符串与 json 互转

这里我在我的另一篇文章 [查询字符串与 JSON 互转](./查询字符串与JSON互转.md) 中有写到了，这里就不在做过多叙述了

## 5.提取 url 中的 Query 对象

```js
function getQueryObject(url) {
  url = url == null ? window.location.href : url
  const search = url.substring(url.lastIndexOf('?') + 1)
  const obj = {}
  const reg = /([^?&=]+)=([^?&=]*)/g
  search.replace(reg, (rs, $1, $2) => {
    const name = decodeURIComponent($1)
    let val = decodeURIComponent($2)
    val = String(val)
    obj[name] = val
    return rs
  })
  return obj
}
```

## 6.深拷贝

浅拷贝就不说了，`Object.assign`就能解决了，有关 js 对象拷贝这里也不做过多的赘述，随便一搜就有各种相关的。这里就贴一个深拷贝的相关代码。

```js
function deepClone(source) {
  if (!source && typeof source !== 'object') {
    throw new Error('error arguments', 'deepClone')
  }
  const targetObj = source.constructor === Array ? [] : {}
  Object.keys(source).forEach((keys) => {
    if (source[keys] && typeof source[keys] === 'object') {
      targetObj[keys] = deepClone(source[keys])
    } else {
      targetObj[keys] = source[keys]
    }
  })
  return targetObj
}
```
