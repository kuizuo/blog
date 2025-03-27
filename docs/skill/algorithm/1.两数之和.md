---
id: two-sum
slug: /algorithm/two-sum
title: 两数之和
authors: kuizuo
tags: [algorithm]
keywords: [algorithm]
---

## 暴力枚举

```js
var twoSum = function (nums, target) {
  const n = nums.length

  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      if (nums[i] + nums[j] === target && i !== j) {
        return [i, j]
      }
    }
  }
}
```

## 哈希表

```js
var twoSum = function (nums, target) {
  const map = new Map()

  for (let i = 0; i < nums.length; i++) {
    if (map.has(target - nums[i])) {
      return [map.get(target - nums[i]), i]
    }
    map.set(nums[i], i)
  }
}
```
