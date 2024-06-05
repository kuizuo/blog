---
id: js-implement-function-cache
slug: /js-implement-function-cache
title: JS实现函数缓存
date: 2021-11-22
authors: kuizuo
tags: [javascript]
keywords: [javascript]
---

<!-- truncate -->

## 原理

- 闭包
- 柯里化

- 高阶函数

## 例子：求和

正常的循环累加代码

```javascript
function add() {
  let sum = 0
  for (let i = 0; i < arguments.length; i++) {
    sum += arguments[i]
  }
  return sum
}
```

使用数组的 reduce 方法

```javascript
function add() {
  var arr = Array.prototype.slice.call(arguments)
  return arr.reduce(function (prev, cur) {
    return prev + cur
  }, 0)
}
```

但多次传入同样的参数 如 `add(1, 2, 3)` 都将执行运算对应的次数，将会耗费一定的性能。

### 使用函数缓存

使用闭包，将每次运算的参数与结果存入置 cache 对象中，如果 cache 中有，便直接获取，来达到缓存的目的

```javascript
let add = (function () {
  let cache = {}

  return function () {
    let args = Array.prototype.join.call(arguments, ',')
    if (cache[args]) {
      return cache[args]
    }
    let sum = 0
    for (let i = 0; i < arguments.length; i++) {
      sum += arguments[i]
    }
    return (cache[args] = sum)
  }
})()

add(1, 2, 3) // 输出6
add(1, 2, 3) // 直接从cache中获取
```

已经达到缓存的目的了，但这时我想将乘法也想实现缓存的目的，那么又得写一大行这样的代码，同时原本求和的代码又想单独分离出来，就可以使用代理模式，具体演示如下

### 代理模式

#### 创建缓存代理的工厂

```javascript
let memoize = function (fn) {
  let cache = {}
  return function () {
    let args = Array.prototype.join.call(arguments, ',')
    if (args in cache) {
      return cache[args]
    }
    return (cache[args] = fn.apply(this.arguments))
  }
}
```

那么通过`memoize` 就能将函数运行后的结果给缓存起来，如

```javascript
let add1 = memoize(add)

add1(1, 2, 3) // 输出6
add1(1, 2, 3) // 直接从cache中获取
```

我们只需要编写我们正常的业务逻辑（加法，乘法等），然后通过 memoize 调用 便可达到缓存的目的

同理乘法

```javascript
function mult() {
  let a = 0
  for (let i = 0; i < arguments.length; i++) {
    a *= arguments[i]
  }
  return a
}

let mult1 = memoize(mult)

mult1(1, 2, 3) // 输出6
mult1(1, 2, 3) // 直接从cache中获取
```
