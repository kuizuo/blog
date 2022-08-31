---
id: mysql-replace-function
slug: /mysql-replace-function
title: mysql替换函数replace
date: 2021-01-07
tags: [mysql, database]
keywords: [mysql, database]
---

## 1、前言

当初设计题库数据库时，没考虑周全，存在多题目，题目不标准，比如下面这样

![image-20210107044832103](https://img.kuizuo.cn/image-20210107044832103.png)

题目前面的【单选题】【判断题】怎么能忍，于是就百度 mysql 文本替换 第一篇文章就解决了我的问题，于是我也顺手记录一下，以防下次使用

> 参考链接 [mysql 替换函数 replace()实现 mysql 替换指定字段中的字符串](https://blog.csdn.net/qq_36663951/article/details/78791138)

## 2、替换函数 replace()

最关键的也就是这个函数了，先看看我的 SQL 语句是怎么写的

```sql
UPDATE `kz_answer` SET `topic` = replace (`topic`,'【单选题】','') WHERE `topic` LIKE '%【单选题】%'
```

其实也就是 UPDATE 更新语句，然后通过 WHERE 子句与 LIKE 模糊判断，最后将字段给修改了。会点 MySQL 的上面代码一眼就懂，不写了，还要折腾题库接口和题库存储。

该函数是多字节安全的，也就是说你不用考虑是中文字符还是英文字符。
