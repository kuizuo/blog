---
title: Vue响应式数据之Array
date: 2022-05-12
authors: kuizuo
tags: [vue, js]
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
  value.__prot-o__ = arrayMethods
}
```

至于以及其他数组方法，这里仅做代码实现，由于篇幅有限，不做细说。



### 缺陷

通过一系列原型方法修改来实现响应式也有缺陷，尤其对于数组特殊变动并没有对应原型方法。

1. 利用索引直接设置一个数组项时，例如：`vm.items[indexOfItem] = newValue`
2. 修改数组的长度时，例如：`vm.items.length = newLength`

## Proxy

但在 Vue3 也可以使用 Proxy 来监听，不过先在 set 方法中删除`if (target[property] === newValue) return`

```typescript
let target = [1, 2, 3]
function defineReactive(target) {
  return new Proxy(target, {
    get(target, property) {
      console.log(`对属性${property}取值为${target[property]}`)
      return target[property]
    },
    set(target, property, newValue) {
      // if (target[property] === newValue) return
      target[property] = newValue
      console.log(`对属性${property}赋值为${target[property]}`)
      return true
    },
    deleteProperty(target, property) {
      console.log(`删除属性为${property}`)
      delete target[property]
    },
  })
}

let arr = defineReactive(target)

arr[0]
arr.push(1)
```
