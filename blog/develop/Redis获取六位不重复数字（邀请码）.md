---
slug: redis-get-six-digit-number-invitation-code
title: Redis获取六位不重复数字（邀请码）
date: 2021-08-11
authors: kuizuo
tags: [redis]
keywords: [redis]
---

<!-- truncate -->

## 需求

针对每一个用户（用户量在 10w 以下）随机生成的邀请码（仅限六位数字），**且不重复**

## 思考

如果能把这个不重复条件去除，那么只需要使用`Math.random`然后取小数点后六位就行了，但可惜要求就是不能重复， 要是重复还得了，到时候注册的时候都不知道奖励给那个邀请码账号。同时还要求邀请码在六位且数字，这就导致即使随机生成的，会有一定的可能出现相同的邀请码。

## 解决方案

### 方案 1

先随机生成一个六位随机数字，然后在存的时候判断数据库是否存在该邀请码，如果存在那么就重新生成一个，直到该邀请码不存在，便存入。

优点：方便，如果用户量不大，完全可以
缺点：用户量上来的情况下，判断邀请码是否存在有可能需要一段时间，并且由于需要判断，故性能欠缺

### 方案 2

利用 redis 的 set 数据类型，先将所有的邀请码存入到 set 中，然后通过 srandmember 随机获取一个数值，在通过 srem 删除该元素即可。

或者也可以通过 list 队列，将预先随机生成的六位不重复数字的所有集合统统添加到队列中，然后获取的时候通过 rpop 或 lpop 获取

优点：相当于空间换时间，无需判断，后期即便用户量上来的，也完全可以重新生成一批（七位或字母）重新导入

缺点：过于依赖 Redis，redis 服务一旦停止，便无法正常获取数据。

## 实现

既然想都想了，那怎么能不实现呢。我这边仅仅是一个测试 Demo，利用的是方案 2，通过 set 数据类型进行获取相关代码如下

### 预先存入数据

```js
let key = 'code';
function genCode() {
  let num = 999999;
  for (let i = 100000; i < num; i++) {
    client.sadd(key, i, function (err, data) {});
  }
  console.log('数据导入完毕');
}
genCode();
```

### 获取数据并删除

```js
// 输出所有成员
client.smembers(key, function (err, data) {
  console.log(data);
});

// 随机获取一个数据
client.srandmember(key, function (err, data) {
  console.log(data);
  client.srem(key, data, function (err, data) {});
});
```

整体耗时不会超过 3 分钟

通过`console.time()`获取数据耗时如下

```
default: 0.174ms
```
