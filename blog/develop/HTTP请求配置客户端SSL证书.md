---
slug: http-config-client-ssl-certificate
title: HTTP请求配置客户端SSL证书
date: 2022-02-17
authors: kuizuo
tags: [http, ssl]
keywords: [http, ssl]
---

在学习安卓逆向的时候，遇到一个 APP，服务端检测请求的 SSL 证书，需要提交 SSL 证书上去才能正常发送请求。而在开启抓包和协议复现的时候，请求是能正常发出去，但是服务器会返回 400 错误。于是便有了这篇文章来记录下。

<!-- truncate -->

## 说明

由于是服务端效验客户端发送的证书，所以使用代理服务器（FD，Charles 等）抓包是会替换本地证书，当服务器效验客户端发送的证书与服务器内的证书不一致，那么就直接返回 400 错误，实际上请求还是能够发送出去，只是被服务器给拒绝了。俗称**双向认证**

所以解决办法就是在请求的时候，将正确的证书也一同发送过去，这样服务端效验时就会将正常的响应结果返回给客户端，也就是**配置自定义证书**。

### 例子

APP 例子：隐约

具体如何拉取证书，就是安卓逆向相关的部分了，这里我也只提供证书文件，不提供 app。

贴上下载地址及密码

证书: https://img.kuizuo.cn/cert.p12

密码: `xinghekeji888.x`

### 证书转化

[证书格式转换 (myssl.com)](https://myssl.com/cert_convert.html)

[SSL 在线工具-在线证书格式转换-证书在线合并-p12、pfx、jks 证书在线合成解析-SSLeye 官网](https://www.ssleye.com/ssltool/jks_pkcs12.html)

也可使用 OpenSSL 工具来进行转化证书

## HTTP 发送请求

### node 的 axios

```javascript
const axios = require('axios').default
const fs = require('fs')
const https = require('https')

axios
  .post(
    `https://app.yyueapp.com/api/passLogin`,
    {
      mobile: '15212345678',
      password: 'a123456',
    },
    {
      httpsAgent: new https.Agent({
        cert: fs.readFileSync('./cert.cer'),
        key: fs.readFileSync('./cert.key'),
        // pfx: fs.readFileSync('./cert.p12'),
        // passphrase: 'xinghekeji888.x,
      }),
    },
  )
  .then((res) => {
    console.log(res.data)
  })
  .catch((error) => {
    console.log(error.response.data)
  })
```

如果没有配置 httpsAgent，也就是没有配置证书，那么返回 400 错误 `400 No required SSL certificate was sent`。

配置成功将会得到正确的响应结果

```javascript
{ code: 998, msg: '系统维护中...', data: null }
```

### python 的 requests

requests 不支持 p12 格式的证书，所以需要使用其他的证书格式，如下

```python
import requests

r = requests.post('https://app.yyueapp.com/api/passLogin', data={
                  'mobile': '15212345678', 'password': 'a123456'}, cert=('./cert.cer', './cert.key'))
print(r.status_code)
print(r.text)
```
