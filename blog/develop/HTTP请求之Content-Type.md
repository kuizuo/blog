---
slug: content-type-of-http-request
title: HTTP请求之Content-Type
date: 2020-12-12
authors: kuizuo
tags: [http]
keywords: [http]
---

<!-- truncate -->

## Content-type

先看一条 HTTP 请求

```http
POST https://xxx.kuizuo.cn/v2/login HTTP/1.1
Host: xxx.kuizuo.cn
Connection: keep-alive
Content-Length: 121
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
// Content-Type: application/json;charset=UTF-8
Accept: application/json, text/plain, */*

{"username":"kuizuo","password":"a12345678"}
```

上面那个请求发送到我的服务器，服务器却接收到的是这样一串值

```json
{ "{\"username\":\"kuizuo\",\"password\":\"a12345678\"}": "" }
```

很显然，它把 json 格式解析成了 x-www-form-urlencoded。

一个很简单的登录请求，注意一个协议头`Content-Type`，它决定了你的数据发送到服务端上会是什么格式。

```
类型格式：type/subtype(;parameter)?
type 主类型，任意的字符串，如text，如果是*号代表所有；
subtype 子类型，任意的字符串，如html，如果是*号代表所有；
parameter 可选，一些参数，如Accept请求头的q参数， Content-Type的charset参数。
```

常见的媒体格式类型如下：

- text/html ： HTML 格式

- text/plain ：纯文本格式

- text/xml ： XML 格式

- image/gif ：gif 图片格式

- image/jpeg ：jpg 图片格式

- image/png：png 图片格式

  以 application 开头的媒体格式类型：

- application/xhtml+xml ：XHTML 格式

- application/xml ： XML 数据格式

- application/atom+xml ：Atom XML 聚合格式

- application/json ： JSON 数据格式

- application/pdf ：pdf 格式

- application/msword ： Word 文档格式

- application/octet-stream ： 二进制流数据（如常见的文件下载）

- application/x-www-form-urlencoded ： form 表单数据被编码为 key/value 格式（通过=与&拼接）发送到服务器（表单默认的提交数据的格式）格式如: username=kuizuo&password=a12345678

  另外一种常见的媒体格式是上传文件之时使用的：

- multipart/form-data ： 需要在表单中进行文件上传时，就需要使用该格式

实际上遇到最多的也就是 text/html，text/plain，application/json，application/x-www-form-urlencoded 这几个。

> 参考资料 [Http 请求中 Content-Type](https://www.cnblogs.com/klb561/p/10090540.html)

### 说说我那时候的情况

这是在我帮别人分析登录算法的时候，由于协议头中少添加了一个`Content-Type`，导致我发送的数据，服务端解析不了，收到了这样的响应

```json
{ "code": 500001, "message": "亲，我们的系统目前忙碌中或无法回应，请将此问题回报给我们的客服人员。 错误代碼(68523)", "data": null }
```

然而实际响应应该是这样的

```json
{ "code": 400020, "message": "密码错误", "data": "验证码错误" }
```

原因就是因为协议头没有添加`Content-Type: application/json;charset=UTF-8`所导致的。因为这个，坑了我近一个小时，还一直以为是数据错误，没想到仅仅只是少加了一些协议头导致的请求数据格式错误。

一个印象很深刻的教训，模拟 HTTP 请求的时候，一定不要吝啬补全协议头，不然坑的就是自己了。我已经给坑过两次了，所以在特意想借此记录一下，免得下次又是一番折腾。写个注意，醒目一点。

:::danger

发送的是 JSON 格式数据，切记一定要添加上协议头`Content-Type: application/json;charset=UTF-8`！！！

:::
