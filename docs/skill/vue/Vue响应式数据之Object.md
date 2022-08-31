---
id: vue-reactive-data-object
slug: /vue-reactive-data-object
title: Vue响应式数据之Object
date: 2022-05-10
authors: kuizuo
tags: [vue, javascript]
keywords: [vue, javascript]
---

在阅读《深入浅出 Vue.js》与《Vue.js 设计与实现》，了解到 vue 是如何侦测数据，同时自己在接触 js 逆向时也常常会用到。于是就准备写篇 js 如何监听数据变化，这篇为监听 Object 数据。

<!-- truncate -->

## Object.defineproperty

```javascript
const data = {
  username: 'kuizuo',
  password: 'a123456',
}

function defineReactive(data, key, val) {
  Object.defineProperty(data, key, {
    enumerable: true,
    configurable: true,
    get() {
      console.log('GET', val)
      return val
    },
    set(newVal) {
      if (val === newVal) return

      val = newVal
      console.log('SET', val)
    },
  })
}

function observe(data) {
  Object.keys(data).forEach(function (key) {
    defineReactive(data, key, data[key])
  })
}

observe(data)

data.username
data.username = '愧怍'
```

从上面的代码中就可以发现，只要取值与赋值就会进入 get 和 set 函数内，在这里面便可以实现一些功能，例如 Vue 中收集依赖，在想监听浏览器中 cookies 的取值与赋值，就可以使用如下代码

```javascript
!(function () {
  let cookie = document.cookie
  Object.defineProperty(document, 'cookie', {
    get() {
      console.log('cookie get', cookie)
      return cookie
    },
    set(newVal) {
      cookie = newVal
      console.log('cookie set', cookie)
    },
  })
})()
```

使用 object.defineproperty 能监听对象上的某个属性修改与获取，但是无法监听到对象属性的增和删。这在 es5 是无法实现的，因为还不支持[元编程](https://baike.baidu.com/item/元编程/6846171)。这也就是为什么 Vue2 中[对于对象](https://cn.vuejs.org/v2/guide/reactivity.html#对于对象)无法监听到 data 的某个属性增加与删除了

```javascript
var vm = new Vue({
  data: {
    a: 1,
  },
})

// `vm.a` 是响应式的

vm.b = 2
// `vm.b` 是非响应式的
```

## Proxy 与 Reflect

但在 ES6 中提供了 Proxy 可以实现元编程，同时 Vue3 也使用 Proxy 来重写[响应式系统](https://v3.cn.vuejs.org/guide/reactivity.html)。所以就很有必要去了解该 API

```javascript
function reactive(target) {
  return new Proxy(target, {
    get(target, key) {
      const res = target[key]
      console.log('GET', key, res)
      return res
    },
    set(target, key, newValue) {
      target[key] = newValue
      console.log('SET', key, newValue)
    },
    deleteProperty(target, key) {
      console.log('DELETE', key)
      delete target[key]
    },
  })
}
```

但上述写法中使用了`target[key]` 是能获取到 target 的值，但可能会存在一定隐患（如 this 问题），所以更推荐使用`Reflect`对象的方法，如下

```javascript
function reactive(target) {
  return new Proxy(target, {
    get(target, key, receiver) {
      const res = Reflect.get(target, key, receiver)
      console.log('GET', key, res)
      return res
    },
    set(target, key, newValue, receiver) {
      const res = Reflect.set(target, key, newValue, receiver)
      console.log('SET', key, newValue)
      return res
    },
    deleteProperty(target, key) {
      const res = Reflect.deleteProperty(target, key)
      console.log('DELETE', key)

      return res
    },
  })
}
```

调用如下

```javascript
const target = {
  foo: 1,
  bar: 1,
}

let p = reactive(target)
p.foo++
delete p.bar

console.log(target)
```

输出内容如下

```
GET foo 1
SET foo 2
DELETE bar
{ foo: 2 }
```

其中这里的 get,set,deleteProperty 可以拦截到对象属性的取值，赋值与删除的操作。相比 Object.defineproperty 除了好用外，可操作空间也大。

### [this 问题](https://es6.ruanyifeng.com/#docs/proxy#this-问题)

如果 target 对象存在 this，那么不做任何拦截的情况下，target 的 this 所指向的是 target，而不是代理对象 proxy

```javascript
const target = {
  m: function () {
    console.log(this === proxy)
  },
}
const handler = {}

const proxy = new Proxy(target, handler)

target.m() // false
proxy.m() // true
```

具体可看：[this 问题](https://es6.ruanyifeng.com/#docs/proxy#this-问题)

### 区别增加和修改

对象属性增加还是修改都会触发 set，所以需要在 set 中区别增加和修改，

```javascript {6}
function reactive(target) {
  return new Proxy(target, {
    set(target, key, newVal, receiver) {
      const oldVal = target[key]

      const type = Object.prototype.hasOwnProperty.call(target, key) ? 'SET' : 'ADD'
      const res = Reflect.set(target, key, newVal, receiver)

      if (oldVal !== newVal) {
        console.log(type, key, newValue)
      }

      return res
    },
  })
}
```

### 深响应

如果数据含多层对象，像

```javascript
const p = reactive({ foo: { bar: 1 } })

// 将不会触发
p.foo.bar = 2
```

需要将 get 中包装为

```javascript {6-9}
function reactive(target) {
  return new Proxy(target, {
    get(target, key, receiver) {
      const res = Reflect.get(target, key, receiver)

      if (typeof res === 'object' && res !== null) {
        // 将其包装成响应式数据
        return reactive(res)
      }

      console.log('GET', key, res)
      return res
    },
  })
}
```

## 最终代码

在稍加对 console.log 进行封装，最终实现对 Object 代理的代码如下

```javascript
const target = {
  foo: 1,
  bar: 1,
}

function log(type, key, val) {
  console.log(type, key, val)
}

function reactive(target) {
  return new Proxy(target, {
    get(target, key, receiver) {
      const res = Reflect.get(target, key, receiver)

      if (typeof res === 'object' && res !== null) {
        return reactive(res)
      }

      log('GET', key, res)
      return res
    },
    set(target, key, newVal, receiver) {
      const oldVal = target[key]

      const type = Object.prototype.hasOwnProperty.call(target, key) ? 'SET' : 'ADD'
      const res = Reflect.set(target, key, newVal, receiver)

      if (oldVal !== newVal) {
        log(type, key, newVal)
      }

      return res
    },
    deleteProperty(target, key) {
      const hadKey = Object.prototype.hasOwnProperty.call(target, key)

      const res = Reflect.deleteProperty(target, key)

      if (res && hadKey) {
        log('DELETE', key, res)
      }

      return res
    },
  })
}

const p = reactive(target)
p.a = 1
p.foo++
delete p.bar

console.log(target)
```

当然，可以将 log 函数的进一步的封装，如 Vue3 中 get 方法的*track*，set 方法中的*trigger*。更好的监听数据变化以及执行自定义函数等等，这里只谈论监听数据变化。

此外 Proxy 还不只有监听对象的属性，还可以监听对象方法等等，具体可在[MDN](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Global_Objects/Proxy/Proxy)中查询相对于的拦截器。

## 参考

> [Proxy - ECMAScript 6 入门 (ruanyifeng.com)](https://es6.ruanyifeng.com/#docs/proxy)
>
> [Proxy() 构造器 - JavaScript | MDN (mozilla.org)](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Global_Objects/Proxy/Proxy)
>
> 《Vue.js 设计与实现》
>
> 《深入浅出 Vue.js》
