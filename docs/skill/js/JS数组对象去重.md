---
id: js-array-object-unique
slug: /js-array-object-unique
title: JS数组对象去重
date: 2021-07-05
authors: kuizuo
tags: [javascript]
keywords: [javascript]
---

<!-- truncate -->

参考 [数组对象去重](https://www.nodejs.red/#/javascript/base?id=数组去重的三种实现方式)

数据如下:

```js
[{ name: 'zs', age: 15 }, { name: 'lisi' }, { name: 'zs' }]
```

想要将 name 为 zs 的数据去重，优先保留第一条相同数据

## 解决方法

### reduce 去重

```js
let hash = {}

function unique(arr, initialValue) {
  return arr.reduce(function (previousValue, currentValue, index, array) {
    hash[currentValue.name] ? '' : (hash[currentValue.name] = true && previousValue.push(currentValue))

    return previousValue
  }, initialValue)
}

const uniqueArr = unique([{ name: 'zs', age: 15 }, { name: 'lisi' }, { name: 'zs' }], [])

console.log(uniqueArr) // uniqueArr.length == 2
```

### lodash 工具库去重

[Lodash Documentation](https://lodash.com/docs/4.17.15#uniqBy)

```js
_.uniqBy([{ x: 1 }, { x: 2 }, { x: 1 }], 'x')

// => [{ 'x': 1 }, { 'x': 2 }]

// 指定条件
_.uniqBy([2.1, 1.2, 2.3], Math.floor)
// => [2.1, 1.2]
```

想要所有对象属性都一样才去重也简单

```js
var objects = [
  { x: 1, y: 2 },
  { x: 2, y: 1 },
  { x: 1, y: 2 },
]

_.uniqWith(objects, _.isEqual)
// => [{ 'x': 1, 'y': 2 }, { 'x': 2, 'y': 1 }]
```
