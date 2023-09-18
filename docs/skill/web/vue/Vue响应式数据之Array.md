---
id: vue-reactive-data-array
slug: /vue-reactive-data-array
title: Vue响应式数据之Array
date: 2022-05-12
authors: kuizuo
tags: [vue, javascript]
keywords: [vue, javascript]
---

<!-- truncate -->

## 修改原型方法

上面所说到的是对象的响应式，但 js 中不止有对象，还有数组，数组能用 Object.defineProperty 方式来监听吗，能

```javascript
const original = Array.prototype.push
Array.prototype.push = function (...args) {
  console.log('ADD', args)
  return original.apply(this, args)
}

const arr = [1, 2, 3]

arr.push(4)
// 输出 ADD 4
```

当然，这里修改了全局的 Array 原型，对于一些不必要的数据也会监听到，在 Vue2 中会进入 Observer 构造函数体，判断 value 是否为数组，是则对 value 原型赋值为修改后的 arrayMethods。

```javascript
const arrayProto = Array.prototype
const arrayMethods = Object.create(arrayProto)

if (Array.isArray(value)) {
  value.__proto__ = arrayMethods
}
```

至于以及其他数组方法，这里仅做代码实现，由于篇幅有限，不做细说。

```javascript
const arrayProto = Array.prototype
const arrayMethods = Object.create(arrayProto)

function def(obj, key, val, enumerable) {
  Object.defineProperty(obj, key, {
    value: val,
    enumerable: !!enumerable,
    writable: true,
    configurable: true,
  })
}

;['push', 'pop', 'shift', 'unshift', 'splice', 'sort', 'reverse'].forEach(function (method) {
  const original = arrayProto[method]

  def(arrayMethods, method, function mutator(...args) {
    const result = original.apply(this, args)
    let inserted
    switch (method) {
      case 'push':
      case 'unshift':
        inserted = args
        break
      case 'splice':
        inserted = args.slice(2)
        break
    }

    if (inserted) {
      console.log('ADD', args)
    }
    return result
  })
})

function observerArray(arr) {
  arr.__proto__ = arrayMethods
  return arr
}

let arr = observerArray([1, 2, 3])

arr.push(4)
arr.unshift(0)

console.log(arr)
```

输出如下

```
ADD [ 4 ]
ADD [ 0 ]
[ 0, 1, 2, 3, 4 ]
```

### 缺陷

通过一系列原型方法修改来实现响应式也有缺陷，尤其对于数组特殊变动并没有对应原型方法。

1. 利用索引直接设置一个数组项时，例如：`vm.items[indexOfItem] = newValue`
2. 修改数组的长度时，例如：`vm.items.length = newLength`

## Proxy

但在 Vue3 也可以使用 Proxy 来监听（代理）数据，先引用监听[Object 中的最终代码](/docs/vue-reactive-data-object/#最终代码)，对其稍加修改一下，看看效果

```javascript
function log(type, index, val) {
  console.log(type, index, val)
}

function reactive(target) {
  return new Proxy(target, {
    get(target, key, receiver) {
      const res = Reflect.get(target, key, receiver)

      if (typeof res === 'object' && res !== null) {
        return reactive(res)
      }

      if (Array.isArray(target) && isNaN(key)) {
        return res
      }

      log('GET', key, res)
      return res
    },
    set(target, key, newVal, receiver) {
      const oldVal = target[key]

      const type = Array.isArray(target) ? (Number(key) < target.length ? 'SET' : 'ADD') : Object.prototype.hasOwnProperty.call(target, key) ? 'SET' : 'ADD'

      const res = Reflect.set(target, key, newVal, receiver)

      if (Array.isArray(target) && key === 'length') {
        // log('Length', null, target.length)
      } else {
        if (oldVal !== newVal) {
          log(type, key, newVal)
        }
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

const target = [1, 2, 3]
const p = reactive(target)

p[1]
p.push(4)
p[2] = 100
p.pop()
console.log(p)
```

执行结果

```
GET 1 2
ADD 3 4
SET 2 100
GET 3 4
DELETE 3 true
[ 1, 2, 100 ]
```

实际上，以上代码就已经能监听数组成员新增，修改与删除了。但对于一些特殊方法（数组遍历，寻找成员），还需要修改其原型方法，就需要像 Vue2 对原型方法那样操作。不过在监听数据变化上，用处并不是特别大，主要体现在依赖收集以及副作用函数的调用上。
