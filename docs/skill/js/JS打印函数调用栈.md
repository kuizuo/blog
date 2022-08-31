---
id: js-print-stack-of-function
slug: /js-print-stack-of-function
title: JS输出函数调用栈
date: 2021-10-15
authors: kuizuo
tags: [javascript, callstack]
keywords: [javascript, callstack]
---

<!-- truncate -->

最近在编写 JS 逆向 hook 类插件，然后需要获取当前代码执行时所在的位置，方便代码定位，于是就总结下 JavaScript 如何输出函数调用栈。

## 演示代码

```javascript
function main() {
  let a = fun('hello world')
  console.log(a)
}

function fun(a) {
  return a
}

main()
```

## 方法

### console.trace()

使用如下

```javascript {7}
function main() {
  let a = fun('hello world')
  console.log(a)
}

function fun(a) {
  console.trace('fun')
  return a
}

main()
```

输出结果为

```
Trace: fun
    at fun (c:\Users\zeyu\Desktop\demo\main.js:7:11)
    at main (c:\Users\zeyu\Desktop\demo\main.js:2:11)
    at Object.<anonymous> (c:\Users\zeyu\Desktop\demo\main.js:11:1)    at Module._compile (node:internal/modules/cjs/loader:1095:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1124:10)
    at Module.load (node:internal/modules/cjs/loader:975:32)
    at Function.Module._load (node:internal/modules/cjs/loader:816:12)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47
hello world
```

其中`console.trace()`可以传入参数，最终都将直接输出在 Trace 后面，如这里的 fun，但只能在控制台中输出

不过 IE6 并不支持，不过应该也没人用了吧

### arguments.callee.caller

在**非严格模式**下，可以直接输出`arguments`，便会打印出所调用的参数，以及调用的函数，使用如下

```javascript {7-10}
function main() {
  let a = fun('hello world')
  console.log(a)
}

function fun(a) {
  console.log(fun.caller.toString())
  console.log(arguments)
  console.log(arguments.callee.toString())
  console.log(arguments.callee.caller.toString())

  return a
}

main()
```

输出结果为

```
function main() {
  let a = fun('hello world')
  console.log(a)
}
[Arguments] { '0': 'hello world' }
function fun(a) {
  console.log(fun.caller.toString())
  console.log(arguments)
  console.log(arguments.callee.toString())
  console.log(arguments.callee.caller.toString())

  return a
}
function main() {
  let a = fun('hello world')
  console.log(a)
}
hello world
```

成功的将我们当前运行的函数给打印了出来（这里使用 toString 方便将函数打印出来），而上级的函数的话通过`fun.caller`和`arguments.callee.caller`都能得到。

![image-20211015094231693](https://img.kuizuo.cn/image-20211015094231693.png)

`caller`便是调用的上层函数，也就是这里的 main 函数，不难发现每个 caller 对象下都有一个 caller 属性，也就是`caller`的上层函数，由于我这里是 node 环境，所以这里的 caller 的 caller 我也不知道是个什么玩意。。。反正这不是所要关注的重点，重点是**`fun.caller`和``arguments.callee.caller`便可以打印出上层函数**，直到 caller 为空

另外圈的`[[FunctionLocation]]`便是函数所在位置，不过可惜是，这个并不是 caller 的属性，仅供 js 引擎使用的，所以无法输出。

总结下来：

**fun.caller == arguments.callee.caller 代表 fun 的执行环境 (上层函数)**

**arguments.callee 代表的是正在执行的 fun**

**前提: 非严格模式下**

### new Error().stack

众所周知，程序一旦出错 W，便会直接停止运行，同时输出报错信息，而这里的报错信息就包括调用的函数以及具体位置，相对于上面的方法而言，这个能直接在执行环境中输出，而不是单纯的在控制台显示。

同样还是上面的代码

```javascript {7,11-14}
function main() {
  let a = fun('hello world')
  console.log(a)
}

function fun(a) {
  printStack()
  return a
}

function printStack() {
  let stack = new Error().stack
  console.log(stack)
}

main()
```

输出的结果为一串字符串，如下

```
Error
    at printStack (c:\Users\zeyu\Desktop\demo\main.js:12:16)
    at fun (c:\Users\zeyu\Desktop\demo\main.js:7:3)
    at main (c:\Users\zeyu\Desktop\demo\main.js:2:11)
    at Object.<anonymous> (c:\Users\zeyu\Desktop\demo\main.js:16:1)    at Module._compile (node:internal/modules/cjs/loader:1095:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1124:10)
    at Module.load (node:internal/modules/cjs/loader:975:32)
    at Function.Module._load (node:internal/modules/cjs/loader:816:12)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47
hello world
```

由于结果是个字符串，所以通过 split 分割一下，便能得到调用的函数（fun）以及调用位置（c:\Users\zeyu\Desktop\demo\main.js:7:3），稍加处理一下，如下

```javascript {7}
function main() {
  let a = fun('hello world')
  console.log(a)
}

function fun(a) {
  printStack()
  return a
}

main()

function printStack() {
  const callstack = new Error().stack.split('\n')
  callstack.forEach((s) => {
    let matchArray = s.match(/at (.+?) \((.+?)\)/)
    if (!matchArray) return

    let name = matchArray[1]
    let location = matchArray[2]
    console.log(name, location)
  })
}
```

输出结果如下（由于是 Node 环境，所以会输出一些有关模块 modules 的东西）

```
printStack c:\Users\zeyu\Desktop\demo\main.js:14:21
fun c:\Users\zeyu\Desktop\demo\main.js:7:3
main c:\Users\zeyu\Desktop\demo\main.js:2:11
Object.<anonymous> c:\Users\zeyu\Desktop\demo\main.js:11:1
Module._compile node:internal/modules/cjs/loader:1095:14
Object.Module._extensions..js node:internal/modules/cjs/loader:1124:10
Module.load node:internal/modules/cjs/loader:975:32
Function.Module._load node:internal/modules/cjs/loader:816:12
Function.executeUserEntryPoint [as runMain] node:internal/modules/run_main:79:12
hello world
```

### Error.captureStackTrace

Error 中有一个静态方法，同样用于获取调用栈。演示代码如下

```js
function main() {
  let a = fun('hello world')
  console.log(a)
}

function fun(a) {
  let stack = stackTrace()
  console.log(stack)

  return a
}

function stackTrace() {
  const obj = {}
  Error.captureStackTrace(obj, stackTrace)
  return obj.stack
}

main()
```

效果和`new Error().stack`一样，只不过少了一行~~at printStack (c:\Users\zeyu\Desktop\demo\main.js:12:16)~~ 的输出。

不过一般用法如下

```js
function MyError() {
  Error.captureStackTrace(this, MyError)
}

// 如果没有向captureStackTrace传递MyError参数，则在访问.stack属性时，MyError及其内部信息将会出现在堆栈信息中。当传递MyError参数时，这些信息会被忽略。
new MyError().stack
```

其中`Error.captureStackTrace()`源自[V8 引擎的 Stack Trace API](https://link.segmentfault.com/?enc=u3YSqa2uqpuK4qOK1mcE%2BQ%3D%3D.S7z7nzmOapoEFtq3WEZcXOIYfU79dXMyMCaHOU3pUVILksNiqpAhLEXacnQs0fHN)，在自定义 Error 类的内部经常会使用该函数，用以在 error 对象上添加合理的 stack 属性。上文中的 MyError 类即是一个最简单的例子。

```js
function MyError() {
  Error.captureStackTrace(this, MyError)
}

// 如果没有向captureStackTrace传递MyError参数，则在访问.stack属性时，MyError及其内部信息将会出现在堆栈信息中。当传递MyError参数时，这些信息会被忽略。
new MyError().stack
```

[关于 Error.captureStackTrace - SegmentFault 思否](https://segmentfault.com/a/1190000007076507)

## 总结

如果是作为调试阶段，想输出调用栈的话，那么`console.trace()`肯定是个最好的选择，不过只能在控制台显示，无法在运行环境中使用

而`arguments.callee.caller`使用的前提是非严格模式下，所以要使用的话，则需要删除`"use strict";`代码， 但能直接打印出完整的函数，以及调用所传入的参数。

`new Error().stack` 相当于主动报错，由于报错会自动打印报错所在的调用信息，所以能精确的定位到代码的函数名和代码行与列，对于后续要定位代码位置而言优先选择。
