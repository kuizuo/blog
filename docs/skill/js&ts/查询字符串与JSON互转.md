---
id: querystring-and-json-convert
slug: /querystring-and-json-convert
title: 查询字符串与JSON互转
date: 2022-03-15
authors: kuizuo
tags: [http, javascript]
keywords: [http, javascript]
---

<!-- truncate -->

## 查询字符串与 JSON 互转

在发送 HTTP 请求的时候，要模拟一个登录请求的包，而抓到得包如下

```http
POST https://xxx.xxx.com/xxx/login HTTP/1.1
Host: xxx.xxx.com
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1.70.3775.400 QQBrowser/10.6.4208.400
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded

username=kuizuo&password=a12345678
```

但是我要模拟这样的请求就要写成如下方式

```javascript
let url = 'https://xxx.xxx.com/xxx/login'
let username = 'kuizuo'
let password = 'a12345678'

let data = 'username=' + username + '&password=' + password
// or
// let data = `username=${username}&password=${password}`

axios.post(url, data).then(function (res) {
  console.log(res.data)
})
```

像这种 `username=kuizuo&password=a12345678`就称之为查询字符串。显而易见，如果涉及到的参数一多修改显得十分不可靠（**极易改错**）。

所以一般的做法都是将 data 用 js 对象或者用 json 格式表示，像下面这样

```javascript
let username = 'kuizuo'
let password = 'a12345678'
let data = {
  username: username,
  password: password,
}
```

不过请求头是`Content-Type: application/x-www-form-urlencoded`，那么就需要使用工具将其转化为查询字符串了。比方说 node 中自带的 [querystring](http://nodejs.cn/api/querystring.html) 库。

### querystring

```javascript
const qs = require('querystring')

let obj = {
  username: 'kuizuo',
  password: 'a12345678',
}
let data = qs.stringify(obj)
// username=kuizuo&password=a12345678
```

```javascript
const qs = require('querystring')

let data = 'username=kuizuo&password=a12345678'
let json = qs.parse(data)
// { username: 'kuizuo', password: 'a12345678' }
```

### 使用正则与 array.reduce

除了借用 querystring 库之外，实际还可以通过正则匹配与`array.reduce()`，将查询字符串 js 对象。这里就放一下对应的代码：

```javascript
function qs2Json(str) {
  return (str.match(/([^=&]+)(=([^&]*))/g) || []).reduce((a, val) => ((a[val.slice(0, val.indexOf('='))] = val.slice(val.indexOf('=') + 1)), a), {})
}
```

js 对象转查询字符串就相对简单许多了，只需要对 js 对象遍历，然后使用使用&拼接即可。具体转化代码

```javascript
function json2Qs(obj) {
  return Object.keys(obj)
    .map((key) => {
      return key + '=' + obj[key]
    })
    .join('&')
}
```

不过这里遍历的时候还可以添加一些判断的，比如`if (obj[key] === undefined) return ''`，如果键值未定义就返回空字符串，或者清除数组一些为空字符串或 null 等值，这里我就不做过多判断了。

至于要转成 json 格式字符串还是解析 通过`JSON.stringify` 与 `JSON.parse`即可，这里就不在演示了。

最终两者的执行效果

```javascript
let obj = qs2Json('username=kuizuo&password=a12345678')
// {username: "kuizuo", password: "a12345678"}

let param = json2Qs({ username: 'kuizuo', password: 'a12345678' })
// username=kuizuo&password=a12345678
```

### URLSearchParams

除了 querystring，实际上还有一个更好的库 [URLSearchParams](http://nodejs.cn/api/url.html#class-urlsearchparams)，具体的使用如下

```javascript
const params = new URLSearchParams({
  user: 'abc',
  query: 'xyz',
})
console.log(params.toString())
// 'user=abc&query=xyz'
```

```javascript
let params = new URLSearchParams('user=abc&query=xyz')
let json = {}
for (const [key, value] of newSearchParams) {
  json[key] = value
}
console.log(json)
// { user: 'abc', query: 'xyz' }
```

关于`URLSearchParams`更多的可以去官方查看，主要是针对 url 的一个操作，不过我个人更倾向于使用`querystring`，主要原因还是`URLSearchParams`对中文使用的是 js 中的`encodeURIComponent`与`decodeURIComponent`，也就是`UTF8`编码，如果是`GBK`编码就会编码错误。而`querystring`可以指定编码（针对 gbk 的 url 编解码有个[gbk-nice](https://www.npmjs.com/package/gbk-nice)的库 也就是 gbk 版的`encodeURIComponent`）

## Cookie 与 JSON 互转

除了查询字符串需要互转，cookie 数据也可能需要互转。

```javascript
Cookie: _uuid=E4842E42-D3DC-2425-C598-231821AB344B39943infoc; buvid3=C844F66D-EC25-4712-8FF3-A0B65DF172C6155806infoc; sid=cvzaog1s; DedeUserID=35745471; DedeUserID__ckMd5=24ac8c69051043f3; SESSDATA=fc469231%2C1608969153%2C1bd79*61;
```

要转化为下面的方式

```json
{
  "_uuid": "E4842E42-D3DC-2425-C598-231821AB344B39943infoc",
  "buvid3": "C844F66D-EC25-4712-8FF3-A0B65DF172C6155806infoc",
  "sid": "cvzaog1s",
  "DedeUserID": "35745471",
  "DedeUserID__ckMd5": "24ac8c69051043f3",
  "SESSDATA": "fc469231%2C1608969153%2C1bd79*61"
}
```

主要是修改 qs2Json 与 json2Qs 这两个方法，放上对应的 js 代码。

```javascript
function cookies2Obj(cookies) {
  return cookies.split('; ').reduce((a, val) => ((a[val.slice(0, val.indexOf('=')).trim()] = val.slice(val.indexOf('=') + 1).trim()), a), {})
}

function obj2Cookies(obj) {
  return Object.keys(obj)
    .map((key) => {
      return key + '=' + obj[key]
    })
    .join('; ')
}
```

效果就请读者自行尝试了。
