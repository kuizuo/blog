---
slug: mongodb-time-grouping
title: MongoDB按时间分组
date: 2021-08-30
authors: kuizuo
tags: [mongodb]
keywords: [mongodb]
---

<!-- truncate -->

## 需求

需求是这样的，要统计每一周的各个商品的销售记录，使用 echarts 图表呈现，如下图

![image-20210830214556262](https://img.kuizuo.cn/image-20210830214556262.png)

说实话，一开始听到这个需求的时候，我是有点慌的，因为 MongoDB 的分组玩的比较少（Mysql 也差不多），又要按照对应的星期来进行分组，这在之前学习 MongoDB 的时候还没接触过，于是就准备写了这篇文章，来记录下我是如何进行分组的

## MongoDB 的一些时间操作符

时间操作符（专业术语应该不是这个，后文暂且使用这个来描述），**后面会用到的**

```
$dayOfYear: 返回该日期是这一年的第几天。（全年366天）
$dayOfMonth: 返回该日期是这一个月的第几天。（1到31）
$dayOfWeek: 返回的是这个周的星期几。（1：星期日，7：星期六）
$year: 返回该日期的年份部分
$month： 返回该日期的月份部分（between 1 and 12.）
$week： 返回该日期是所在年的第几个星期（between 0 and 53）
$hour： 返回该日期的小时部分
$minute: 返回该日期的分钟部分
$second: 返回该日期的秒部分（以0到59之间的数字形式返回日期的第二部分，但可以是60来计算闰秒。）
$millisecond：返回该日期的毫秒部分（between 0 and 999.）
$dateToString：{ $dateToString: { format: <formatString>, date: <dateExpression> } }
```

## 日期分组

[mongdb 聚合查询日期 统计每天数据](https://blog.csdn.net/wangshu_liang/article/details/95326578?utm_medium=distribute.pc_relevant.none-task-blog-2~default~baidujs_baidulandingword~default-0.essearch_pc_relevant&spm=1001.2101.3001.4242)

关于日期分组的话，我是借鉴了这篇文章，也确实带我解惑了下如何按照日期分组。这里贴下我的代码

```js
let list = await this.goodsModel
  .aggregate([
    { $project: { date: { $dateToString: ['$created_at', 0, 10] } } },
    { $group: { _id: '$date', count: { $sum: 1 } } },
    { $project: { date: '$_id', _id: 0, count: 1 } }, // 再使用$project将_id改名为date
    { $sort: { date: -1 } }, // 根据日期倒序
  ])
  .exec();
```

或者使用时间操作符（更准确一点）

```js
let list = await this.goodsModel
  .aggregate([
    {
      $project: { date: { $dateToString: { format: '%Y-%m-%d', date: '$created_at' } } },
    },
    { $group: { _id: '$date', count: { $sum: 1 } } },
    { $project: { date: '$_id', _id: 0, count: 1 } }, // 再使用$project将_id改名为date
    { $sort: { date: -1 } }, // 根据日期倒序
  ])
  .exec();
```

通过

> 要注意的是，$group 里的属性必须为\_id，不然无法分组

获取到的数据如下（这里只显示一周）

```json
[
  { "count": 54, "date": "2021-08-30" },
  { "count": 29, "date": "2021-08-29" },
  { "count": 16, "date": "2021-08-28" },
  { "count": 17, "date": "2021-08-27" },
  { "count": 12, "date": "2021-08-26" },
  { "count": 6, "date": "2021-08-25" },
  { "count": 0, "date": "2021-08-24" }
]
```

如果只是日期和总商品的话，上面就足以显示对应的数据了，可我要根据星期进行分组的话，就需要替换 MongoDB 的时间转化函数了

## 星期分组

星期分组的话，其实也挺简单的，只需要把上面的

```js
$project: { day: { $dateToString: { format: "%Y-%m-%d", date: "$created_at" } } }
```

替换成

```js
$project: {
  week: {
    $dayOfWeek: {
      date: '$created_at';
    }
  }
}
```

完整代码如下

```js
// 要获取的是一周前的零点时间
let lastweekDay = dayjs(dayjs().add(-7, 'day').format('YYYY-MM-DD')).valueOf();

let list = await this.goodsModel
  .aggregate([
    { $match: { created_at: { $gte: new Date(lastweekDay) } } }, //范围时间
    { $project: { week: { $dayOfWeek: { date: '$created_at' } } } },
    { $group: { _id: '$week', count: { $sum: 1 } } },
    { $project: { week: '$_id', _id: 0, count: 1 } }, // 再使用$project将_id改名为week
    { $sort: { week: 1 } }, // 根据星期正序
  ])
  .exec();
```

获取的结果如下

```js
[
  { count: 29, week: 1 }, // 星期七(日)
  { count: 54, week: 2 }, // 星期一
  { count: 1, week: 3 }, // 星期二
  { count: 9, week: 4 }, // 星期三
  { count: 12, week: 5 }, // 星期四
  { count: 17, week: 6 }, // 星期五
  { count: 16, week: 7 }, // 星期六
];
```

但是，细心的你可能会发现，貌似数据对不上，注当天时间为 2021-08-30，星期一

```json
[
  { "count": 54, "date": "2021-08-30" }, // 星期一
  { "count": 29, "date": "2021-08-29" }, // 星期七(日)
  { "count": 16, "date": "2021-08-28" }, // 星期六
  { "count": 17, "date": "2021-08-27" }, // 星期五
  { "count": 12, "date": "2021-08-26" }, // 星期四
  { "count": 9, "date": "2021-08-25" }, // 星期三
  { "count": 1, "date": "2021-08-24" } // 星期二
]
```

其实只需要把星期向后排序一位就行，因为星期本来就是将星期日作为第一天的，至此，按照星期分组总商品就算完毕了。同理，要按照月份，年份，甚至小时，分钟，都可以直接利用时间操作符转化时间来进行分组。

## 多商品

上述只是获取了总商品了，要细分为多个商品的话，就需要再次利用聚合函数来进行分组了。

这里先演示分组多个商品先，就和正常分组一样

```
let list = await this.goodsModel.aggregate([
{ $group: { _id: "$type", count: { $sum: 1 } } },
]).exec()
```

结果如下（这里输出\_id，是因为没有进行$project 改别名，商品所采用的是数字表示）

```json
[
  { "_id": 1, "count": 111 },
  { "_id": 2, "count": 18 },
  { "_id": 4, "count": 2 },
  { "_id": 3, "count": 16 }
]
```

可以看到统计的是直接是所有商品的总和。

但问题来了，怎么样能分组星期的同时，又对每个商品所在星期进行分组，并且到底是优先分组星期期呢，还是优先分组商品呢，这让我陷入深深的思考。

## 最终实现

首先，绝对不可能使用两次`$group`，要么没有星期分组，要么没有商品分组，于是我就把思路放在`$project`与`$group`内，看看内部是否有其他方法可以实现。

其中`$group`可以将属性添加为数组，注意 `goods: { $push: "$goods" }`

```js
let list = await this.goodsModel
  .aggregate([
    { $match: { created_at: { $gte: new Date(lastweekDay) } } },
    { $project: { week: { $dayOfWeek: { date: '$created_at' } }, goods: 1 } },
    { $group: { _id: '$week', goods: { $push: '$goods' } } },
    { $project: { week: '$_id', _id: 0, goods: 1 } },
    { $sort: { week: 1 } },
  ])
  .exec();
```

可得到的数据却是这样的

```json
[
  {
    "goods": [4, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 1, 1, 1, 1, 1, 1, 1],
    "week": 1
  },
  {
    "goods": [1, 1, 1, 1, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 1, 1, 1, 1, 1, 4, 1, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    "week": 2
  },
  {
    "goods": [1],
    "week": 3
  },
  {
    "goods": [3, 3, 3, 3, 3, 3, 3, 3, 4],
    "week": 4
  },
  {
    "goods": [3, 1, 1, 1, 3, 4, 1, 1, 1, 1, 1, 1],
    "week": 5
  },
  {
    "goods": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 1, 1, 1, 1, 1],
    "week": 6
  },
  {
    "goods": [4, 3, 1, 1, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1],
    "week": 7
  }
]
```

数据很接近了，如果我能把对应的商品总和算起来就行了，但问题是怎么合起来。。。

待会，goods 既然是数组的话，那我能不能`$unwind`全部展开，然后我再来一次聚合，说干就干！

```js
let list = await this.goodsModel
  .aggregate([
    { $match: { created_at: { $gte: new Date(lastweekDay) } } },
    { $project: { week: { $dayOfWeek: { date: '$created_at' } }, goods: 1 } },
    { $group: { _id: '$week', goods: { $push: '$goods' } } },
    { $project: { week: '$_id', _id: 0, goods: 1 } },
    { $sort: { week: 1 } },
    { $unwind: '$goods' },
  ])
  .exec();
```

得到的数据（省略一堆）

```json
[
  { "goods": 4, "week": 1 },
  { "goods": 4, "week": 1 },
  { "goods": 1, "week": 1 },
  { "goods": 1, "week": 1 },
  { "goods": 1, "week": 2 },
  { "goods": 1, "week": 3 },
  { "goods": 1, "week": 4 }
]
```

然后我就卡住了，因为我无论如何都无法分组一个字段的时候，又加以限制条件，要么分组商品的时候，统计的是一周各商品总数据，要么就是分组星期的时候，统计的是总的商品数据。在搜索大量资料后，查看官方一些文档也未果，于是我决定自行写一个 js 函数来进行排序（实在是折腾不动了，能力有限 🥱）

最终完整代码

```js
let lastweekDay = dayjs(dayjs().add(-7, 'day').format('YYYY-MM-DD')).valueOf();

let list = await this.goodsModel
  .aggregate([
    { $match: { created_at: { $gte: new Date(lastweekDay) } } },
    { $project: { week: { $dayOfWeek: { date: '$created_at' } }, goods: 1 } },
    { $group: { _id: '$week', goods: { $push: '$goods' } } },
    { $project: { week: '$_id', _id: 0, goods: 1 } },
    { $sort: { week: 1 } },
    // { $unwind: "$goods" },
  ])
  .exec();

function getEleNums(data) {
  var map = {};
  data.forEach((e) => {
    if (map[e]) {
      map[e] += 1;
    } else {
      map[e] = 1;
    }
  });
  return map;
}

list = list.map((l) => {
  l.goods = getEleNums(l.goods);
  return l;
});
cosnole.log(list);
```

运行后的 list 结果为

```json
[
  { "goods": { "1": 26, "4": 3 }, "week": 1 },
  { "goods": { "1": 53, "4": 3, "5": 1 }, "week": 2 },
  { "goods": { "1": 1 }, "week": 3 },
  { "goods": { "3": 8, "4": 1 }, "week": 4 },
  { "goods": { "1": 9, "3": 2, "4": 1 }, "week": 5 },
  { "goods": { "1": 15, "3": 2 }, "week": 6 },
  { "goods": { "1": 9, "3": 6, "4": 1 }, "week": 7 }
]
```

如果是要 goods 为分组的话，只需要把上面聚合代码中 week 和 goods 替换一下便可。

## 另一种实现方式

专门新建一个表，用于统计每天的销售记录，然后分组的时候就根据该表就行了，具体代码就实现了，思路是挺简单的，但是需要新建一个表，增加记录的时候有需要增加代码，如果业务复杂的话。。。
