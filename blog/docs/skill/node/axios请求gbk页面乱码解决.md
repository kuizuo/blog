---
id: axios-request-gbk-page-encoding-solution
slug: /axios-request-gbk-page-encoding-solution
title: axios请求gbk页面乱码解决
date: 2021-09-19
authors: kuizuo
tags: [node, axios, encode]
keywords: [node, axios, encode]
---

<!-- truncate -->

使用 axios 请求 gbk 编码的网站，将会出现乱码，原因很简单，node 默认字符编码为 utf8，如果要正常显示 gbk 数据的话就需要将 gbk 转 utf8 格式。

## 解决办法

借助`iconv-lite`，不让 axios 自动处理响应数据，添加`responseType`和`transformResponse`参数，演示代码如下

```js
import axios from 'axios'
import * as iconv from 'iconv-lite'

axios
  .get(`https://www.ip138.com/`, {
    responseType: 'arraybuffer',
    transformResponse: [
      function (data) {
        return iconv.decode(data, 'gbk')
      },
    ],
  })
  .then((res) => {
    console.log(res.data)
  })
```

或者不使用`transformResponse`，在响应结束后使用`iconv.decode(res.data, 'gbk')`，使用`transformResponse`相对优雅一点。

如果返回的是 json 格式的话，可以直接`JSON.parse`转为 json 对象（前提得确保是 json 格式，不然解析报错）

```js
return JSON.parse(iconv.decode(data, 'gbk'))
```
