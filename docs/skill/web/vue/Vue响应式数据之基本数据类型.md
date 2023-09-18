---
id: vue-reactive-data-basic-type
slug: /vue-reactive-data-basic-type
title: Vue响应式数据之基本数据类型
date: 2022-05-18
authors: kuizuo
tags: [vue, javascript]
keywords: [vue, javascript]
---

<!-- truncate -->

学过 js 的应该都知道，基本数据类型并非引用类型，直接修改是无法直接拦截的

```javascript
let str = 'vue'
// 无法拦截str
str = 'vue3'
```

很容易想到，用非原始值“包裹”原始值，成一个对象的形式，然后对包裹对象 wrapper 进行 proxy 拦截

```javascript
const wrapper = {
  value: 'vue',
}

const name = reactive(wrapper)

name.value = 'vue3'
```

不出意外(肯定不会出)，将会输出

```text
SET value vue3
```

不难发现，vue2 中对原始值的响应都是将其包裹在 data 函数下返回的对象，并且从上面的代码上来看。但从开发者的角度还需要创建一个包装对象，不易操作的同时，也意味不规范。于是 vue3 封装了 ref 函数，而返回的对象便是响应式的包装对象`reactive(wrapper)`

```javascript
function ref(val) {
  const wrapper = {
    value: val,
  }

  return reactive(wrapper)
}
```

上面的代码便改写为

```javascript
const name = ref('vue')

name.value = 'vue3'
```

## 区别是否为 ref

要区别一个数据是否为 ref，只需要在 ref 中定义一个不可枚举的属性`__v_isRef`值为 true。

```javascript
function ref(val) {
  const wrapper = {
    value: val,
  }

  Object.defineProperty(wrapper, '__v_isRef', {
    value: true,
  })

  return reactive(wrapper)
}
```

## 响应丢失问题

在使用解构赋值的情况下，可能会存在响应丢失的情况，例如

```javascript
const obj = reactive({ foo: 1, bar: 2 })

const user = {
  ...obj,
}

user.foo.value = 3
```

可以发现，并不会输出 SET foo 3，主要由展开运算符...所导致的。上面的 user 就等价于{ foo: 1, bar: 2 }

所以 Vue 则封装了 toRef 和 toRefs 方法，将某个对象的 key 包裹为 ref

```javascript
function toRef(obj, key) {
  const wrapper = {
    get value() {
      return obj[key]
    },
    set value(val) {
      obj[key] = val
    },
  }

  Object.defineProperty(wrapper, '__v_isRef', {
    value: true,
  })

  return wrapper
}

function toRefs(obj) {
  const ret = {}
  for (const key in obj) {
    ret[key] = toRef(obj, key)
  }

  return ret
}

const obj = reactive({ foo: 1, bar: 2 })

const user = {
  ...toRefs(obj),
}

user.foo.value = 3
```

其结果便能正常监听响应式，并输出 SET foo 3

## 自动脱 ref

toRefs 是解决了响应式的问题，但同时也带来了一个新的问题。由于 toRefs 会把响应式数据第一层转为 ref，所以就必须通过 value 来访问属性，这在模板中

```HTML
<p>{{ foo.value }}</p>
```

要是我，我肯定不会使用 Vue。所以 Vue 提供自动脱 ref 的能力，通俗点就是省略.value。

```javascript
function proxyRefs(target) {
  return new Proxy(target, {
    get(target, key, receiver) {
      const value = Reflect.get(target, key, receiver)
      return value.__v_isRef ? value.value : value
    },
    set(target, key, newValue, receiver) {
      const value = target[key]
      if (value.__v_isRef) {
        value.value = newValue
        return true
      }

      return Reflect.set(target, key, newValue, receiver)
    },
  })
}
```

将其 user 数据传递给 proxyRefs 函数进行处理，便可省略.value

```javascript
const user = proxyRefs({
  ...toRefs(obj),
})

console.log(user.foo) // 1
```

实际上，在编写 Vue 组件时，setup 返回的数据便会传递给 proxyRefs 函数进行处理。

## 最终代码

```javascript
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

function ref(val) {
  const wrapper = {
    value: val,
  }

  Object.defineProperty(wrapper, '__v_isRef', {
    value: true,
  })

  return reactive(wrapper)
}

function toRef(obj, key) {
  const wrapper = {
    get value() {
      return obj[key]
    },
    set value(val) {
      obj[key] = val
    },
  }

  Object.defineProperty(wrapper, '__v_isRef', {
    value: true,
  })

  return wrapper
}

function toRefs(obj) {
  const ret = {}
  for (const key in obj) {
    ret[key] = toRef(obj, key)
  }

  return ret
}

function proxyRefs(target) {
  return new Proxy(target, {
    get(target, key, receiver) {
      const value = Reflect.get(target, key, receiver)
      return value.__v_isRef ? value.value : value
    },
    set(target, key, newValue, receiver) {
      const value = target[key]
      if (value.__v_isRef) {
        value.value = newValue
        return true
      }

      return Reflect.set(target, key, newValue, receiver)
    },
  })
}
```
