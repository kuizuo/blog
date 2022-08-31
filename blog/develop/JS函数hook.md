---
slug: js-function-hook
title: JS函数hook
date: 2021-11-22
authors: kuizuo
tags: [javascript, hook]
keywords: [javascript, hook]
---

<!-- truncate -->

## 前言

我在阅读《JavaScript 设计模式与开发实践》的第 15 章 装饰者模式，突然发现 JS 逆向中 hook 函数和 js 中的装饰者模式有点像，仔细阅读完全篇后更是对装饰器与 hook 有了更深的理解于是便有了这篇文章来记录一下该操作。

hook 直译的意思为钩子，在逆向领域通常用来针对某些参数，变量进行侦听，打印输出，替换等操作。

## 正文

### 示例代码

```javascript
function add(a, b) {
  return a + b
}
```

### hook 代码

这是一个很简单加法函数，通过 Hook 能获取到这两个参数的值，相当于在 return 之前添加了一句代码`console.log(a,b)`，这样便能输出这两个的值便于分析。那么可以使用如下的方式来复写改函数，而这个方式在 javascript 也就是装饰者模式

```javascript
let _add = add
add = function () {
  console.log('arguments', arguments)
  let result = _add.apply(this, arguments)
  console.log('result', result)
  return result // 如果不需要result 则可直接return _add()
}
```

**完整代码**

```javascript
function add(a, b) {
  return a + b
}

let _add = add
add = function () {
  console.log('arguments', arguments)
  let result = _add.apply(this, arguments)
  console.log('result', result)
  return result
}

add(1, 2)
```

再次调用`add(1,2)`便会输出 arguments 参数以及结果 3，一个很简单 HOOK 就实现了。

不过这个例子可能过于简单，我所要表达的意思是，通过 Hook，定位到我们想 Hook 的函数与变量，通过一系列操作（函数复写，元编程），只要触发该函数或使用（取值，修改）该变量，便能将我们想要的结果（前后的结果（如 加密前，加密后））获取到。这才是我们的目的。

书中给的例子想说明的，想为某个原函数(比如这里的 add)添加一些功能，但该原函数可能是由其他开发者所编写的，那么直接修改原函数本身将可能导致未知 BUG，于是便可以用上面的方式进行复写原函数的同时，还不破坏原函数。

### this 指向问题

但并不是什么函数都能这样操作，或者说这样操作会导致原本函数可能执行不了，比如 this 指向，虽说没有修改原函数，但是原函数的 this 已经给我们更改成当前环境下（如`window`），但有些函数比如`document.getElementById()` 的内部`this`指向为`document`，不妨尝试将下面代码直接复制到控制台中查看会报什么错

```javascript
let _getElementById = document.getElementById
getElementById = function (id) {
  console.log(1)
  return _getElementById(id)
}

let div = getElementById('div')
```

**报错:**

```
Uncaught TypeError: Illegal invocation
    at getElementById (<anonymous>:4:9)
    at <anonymous>:7:11
```

**解决办法:**

只需要将 this 指向设置为 document 即可，代码改写如下

```javascript
let _getElementById = document.getElementById
getElementById = function () {
  console.log(1)
  return _getElementById.apply(document, arguments)
}

let div = getElementById('div')
```

但这样做略显麻烦，且有些函数你可能都不知道 this 的指向，但又想要复写该函数，书中也提及到用 **AOP 装饰函数**

### 用 AOP 装饰函数

先给出 `Function.prototype.before` 和 `Function.prototype.after`方法

```javascript
Function.prototype.before = function (beforefn) {
  let __self = this
  return function () {
    beforefn.apply(this, arguments)
    return __self.apply(this.arguments)
  }
}

Function.prototype.after = function (afterfn) {
  let __self = this
  return function () {
    let ret = __self.apply(this, arguments)
    afterfn.apply(this, [ret])
    return ret
  }
}
```

注：这里 after 与书中略有不同，书中的是将`arguments` 传入`afterfn.apply(this, arguments)`，而我的做法则是将运行后的结果传入 `afterfn.apply(this, [ret])`

那么将我们一开始的加法例子便可以替换为

```javascript
function add(a, b) {
  return a + b
}

add = add
  .before(function () {
    console.log('arguments', arguments)
  })
  .after(function (result) {
    console.log('result', result)
  })
// 切记 这里不能写箭头函数 不然会指向的不是执行中的this 而是代码环境下的this

add(1, 2)

// arguments Arguments(2) [1, 2, callee: ƒ, Symbol(Symbol.iterator): ƒ]
// result 3
```

:::danger
注：这种装饰方式叠加了函数的作用域，如果装饰的链条过长，性能上也会受到一定的影响
:::
但该方法是直接修改原型方法，有些不喜欢污染原型的方式（用原型方式是真的好写），那么做一些变通，将原函数和新函数作为参数传入，代码如下

```javascript
let before = function (fn, beforefn) {
  return function () {
    beforefn.apply(this, arguments)
    return fn.apply(this, arguments)
  }
}
```

add 函数修改如下

```javascript
add = before(add, function () {
  console.log('arguments', arguments)
})

add(1, 2)
```

同样也能达到所要的目的。

## 写后感

```javascript
add = function () {
  console.log('arguments', arguments)
  let result = _add.apply(this, arguments)
  console.log('result', result)
  return result
}
```

```javascript
add = add
  .before(function () {
    console.log('arguments', arguments)
  })
  .after(function (result) {
    console.log('result', result)
  })
```

对比两者方法，前者是对函数进行替换，而后者通过函数原型链将参数与结果通过回调函数的形式进行使用。在不考虑 this 指向，我个人更偏向第一种写法，而第二种写法也确实让我眼前一亮，很巧妙的使用 js 的原型链，从而避免 this 指向的问题。
