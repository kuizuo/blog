---
slug: cookie-of-node-and-browser
title: node与浏览器中的cookie
date: 2020-12-10
authors: kuizuo
tags: [node, axios, cookie]
keywords: [node, axios, cookie]
---

<!-- truncate -->

## 前言

记录一下自己在 nodejs 中使用 http 请求库 axios 中的一些坑（针对 Cookie 操作）

不敢说和别人封装的 axios 相比有多好，但绝对是你能收获到 axios 的一些知识，话不多说，开始

## 封装

一般而言，很少有裸装使用 axios 的，就我涉及的项目来说，我都会将 axios 的 request 封装成一个函数使用，接着在 api 目录下，引用该文件。项目结构一般是这样的：

```
|-- src
	|-- api
		|-- user.js
		|-- goods.js
	|-- utils
		|-- request.js
```

#### request.js

```js
import axios from 'axios'

var instance = axios.create({
  baseURL: process.env.API, // node环境变量获取的Api地址
  withCredentials: true, // 跨域携带Cookies
  timeout: 5000,
})
// 设置请求拦截器
instance.interceptors.request.use(
  (config) => {
    // 在config可以添加自定义协议头 例如token
    config.headers['x-token'] = 'xxxxxxxx'

    return config
  },
  (error) => {
    Promise.error(error)
  },
)

instance.interceptors.response.use(
  (response) => {
    const res = response.data
    // 根据对应的业务代码 对返回数据进行处理

    return res
  },
  (error) => {
    const { response } = error
    // 状态码为4或5开头则会报错
    // 根据根据对应的错误,反馈给前端显示
    if (response) {
      if (response.status == 404) {
        console.log('请求资源路径不存在')
      }
      return Promise.reject(response)
    } else {
      // 断网......
    }
  },
)

export default instance
```

实际上，上面那样的封装就够了，相对于的业务代码就不补充了，如果你的宿主环境是浏览器的话，很多东西你就没必要在折腾的，甚至下面的文章都没必要看（不过还是推荐你看看，会有帮助的）。不过没完，再看看 api 里怎么使用的

#### api/user.js

```js
import request from '@/utils/request'

export function login(data) {
  return request({
    url: '/user/login',
    method: 'post',
    data,
  })
}

export function info() {
  return request({
    url: '/user/info',
    method: 'get',
  })
}

export function logout() {
  return request({
    url: '/user/logout',
    method: 'post',
  })
}
```

看来很简单，没错，就是这么简单，由于是运行在浏览器内的，所以像 cookies，headers 等等都没必要设置，浏览器会自行携带该有的设置，其实想设置也设置不了，主要就是浏览器内置跨域问题。[XMLHttpRequest](https://fetch.spec.whatwg.org/#concept-header-name)

就这？感觉你写的跟别人没什么区别啊

别急，下面才是重头戏。也是我为啥标题只写 axios，而不写 vue-axios 或者 axios 封装的原因。

## 踩坑 Cookies 获取与设置

### 浏览器

运行环境在浏览器中，axios 是无法设置与获取 cookie，获取不到 set-cookies 这个协议头的（即使服务器设置了也没用），先看代码与输出

```js
instance.interceptors.request.use((config) => {
  config.headers['cookie'] = 'cookie=this_is_cookies;username=kuizuo;'
  console.log('config.headers', config.headers)
  return config
})

instance.interceptors.response.use((response) => {
  console.log('response.headers', response.headers)
  return res
})
```

控制台结果：

![image-20201210060704240](https://img.kuizuo.cn/image-20201210060704240.png)

首先，就是圈的这个，浏览器是不许允许设置一些不安全的协议头，例如 Cookie，Orgin，Referer 等等，即便你看到控制台 config.headers 确实有刚刚设置 cookie，但我们输出的也只是 headers 对象，在 Network 中找到这个请求，也同样看不到 Cookie 设置的（这就不放图了）。

同样的，通过响应拦截器中输出的 headers 中也没有 set-cookies 这个字样。网络上很多都是说，添加这么一行代码 `withCredentials: true`，确实，但是没说到重点，都没讲述到怎么获取 cookies 的，因为在**浏览器环境中 axios 压根就获取不到 set-cookies 这个协议头**，实际上 axios 就没必要，因为浏览器会自行帮你获取服务器返回的 Cookies，并将其写入在 Storage 里的 Cookies 中，再下次请求的时候根据同源策略携带上对应的 Cookie。

![image-20201210061627824](https://img.kuizuo.cn/image-20201210061627824.png)

要获取也很简单，vue 中通过`js-cookie`模块即可，而在 electron 中通过`const { session } = require('electron').remote` （electron 可以设置允许跨域，好用）有关更多可以自行查看文档。

那我就是想要设置 Cookies，来跳过登录等等咋办，我的建议是别用浏览器来伪装 http 请求。跨域是浏览器内不可少的一部分，并且要允许跨域过于麻烦。有关跨域，我推一篇文章[10 种跨域解决方案（附终极大招）](https://juejin.cn/post/6844904126246027278)

#### 完整封装代码

::: details 查看代码

```js
import axios from 'axios'
import { MessageBox, Message } from 'element-ui'
import store from '@/store'
import { getToken } from '@/utils/auth'

const service = axios.create({
  baseURL: process.env.VUE_APP_BASE_API,
  withCredentials: true,
  timeout: 5000,
})

service.interceptors.request.use(
  (config) => {
    if (store.getters.token) {
      config.headers['x-token'] = getToken()
    }

    return config
  },
  (error) => {
    Message.error(error)
    return Promise.reject(error)
  },
)

service.interceptors.response.use(
  (response) => {
    const res = response.data
    if (res.code !== 200) {
      Message.error(res.msg || 'Error')

      return Promise.reject(new Error(res.msg || '未知错误'))
    } else {
      return res
    }
  },
  (error) => {
    if (error.response) {
      let res = error.response
      switch (res.status) {
        case 400:
          Message.error(res.msg || '非法请求')
          break
        case 401:
          MessageBox.alert('当前登录已过期，请重新登录', '提示', {
            confirmButtonText: '重新登录',
            type: 'warning',
          }).then(() => {
            store.dispatch('user/logout').then(() => {
              location.reload()
            })
          })
        case 403:
          Message.error(res.msg || '非法请求')
          router.push('/401')
        case 404:
          Message.error(res.msg || '请求资源不存在')
          break
        case 500:
          Message.error(res.msg || '服务器开小差啦')
          break
        default:
          Message.error(res.msg || res.statusText)
      }
    } else {
      Message.error(res.msg || '请检查网络连接状态')
    }

    return Promise.reject(error)
  },
)

export default service
```

:::

### Nodejs

作为 nodejs 的主流 http 框架怎么能只用在浏览器上，nodejs 自然而然可以，不过 nodejs 需要配置的可就多了，在 nodejs 环境中，自然没有浏览器的同源策略，像上面设置不了的 Cookie，现在随便设置，先看看我是怎么封装的：

```js
import axios from 'axios'
import * as http from 'http'
import * as https from 'https'

export async function request(opt) {
  let { url, method = 'get', headers = {}, cookies, data = null } = opt

  headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36'
  headers['Referer'] = url

  if (typeof cookies === 'object') {
    headers['Cookie'] = Object.keys(cookies)
      .map((k) => encodeURIComponent(k) + '=' + encodeURIComponent(cookies[k]))
      .join('; ')
  } else if (typeof cookies === 'string') {
    headers['Cookie'] = cookies
  }

  let options = {
    url: url,
    method: method,
    headers: headers,
    data: queryString.stringify(data),
    httpAgent: new http.Agent({ keepAlive: true }),
    httpsAgent: new https.Agent({
      keepAlive: true,
      rejectUnauthorized: false,
    }),
    timeout: 5000,
  }

  try {
    let res = await this.axios.request(options)

    return res
  } catch (e) {
    console.log(e)
    return e.message
  }
}
```

```js
// test.js
const request = require('./request');

function test() {
  let url = 'https://passport2.chaoxing.com/fanyalogin';
  let data = {
    fid: '-1',
    uname: '15212345678',
    password: 'a12345678',
    refer: 'http%253A%252F%252Fi.mooc.chaoxing.com',
    t: 'true',
  };
  let headers = {};
  let cookies = 'username=kuizuo;uid=123;';
  let res = await request({
    url: url,
    data,
    headers,
    cookies,
  });
  console.log('test -> res.headers', res.headers);
  return res.data;
}

test();
```

测试一下，顺便抓一下包，看看请求包

```http
GET /fanyalogin HTTP/1.1
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36
Referer: https://passport2.chaoxing.com/fanyalogin
Cookie: username=kuizuo;uid=123;
Host: passport2.chaoxing.com
Connection: keep-alive
Content-Length: 100

....
```

有我们自定义的 Cookie，在看看响应的协议头

```js
test -> res.headers {
  server: 'Tengine',
  date: 'Thu, 10 Dec 2020 00:24:15 GMT',
  'content-type': 'text/html',
  'content-length': '1852',
  connection: 'keep-alive',
  vary: 'Accept-Encoding',
  'set-cookie': [
    'JSESSIONID=4365A6B9FD8E0CBADDBDD7E7DA468F7E; Path=/; HttpOnly',
    'route=b2eda164bddd148142a54809ef404926;Path=/'
  ],
  'accept-ranges': 'bytes',
  etag: 'W/"1852-1606444212000"',
}
```

同样能获取到 set-cookie，设置与获取都是这么 so easy ，不同于上面浏览器的配置。

这里我要说明一些东西，在封装代码中有个 httpAgent 与 httpsAgent，你可以字面翻译就是 http 代理，设置它用来干嘛呢，其中有这么个属性 `keepAlive: true` ，如果设置了协议头中的将会有 `Connection: keep-alive`，而不设置则 `Connection: close`，这里也不想过多说明 http 相关知识，如果只是请求一次,那么两者没有太大区别

然而如果我请求一次,过一会(几秒内)又要请求了,那么 keep-alive 一次连接就可以处理多个请求，而 close 则是一次请求后就断开，下次就需要再次连接。说白了就是快一点，而 close 需要不断连接，断开，自然而然就慢。一般来说设置 keep-alive 就对了。

其中在 httpsAgent 中，还有一个属性`rejectUnauthorized: false`，说简单点，就是不抛出验证错误，在抓 nodejs 包的时候，如果不通过设置代理服务器（Fiddler，Charles），而是通过网卡（HTTP Analyzer，Wireshark）就会抛出异常，一般就会出现这种错误。

```
Error: unable to verify the first certificate
```

然而问题就来了，服务端的返回的 set-cookie 该怎么保存。如果只是涉及客户端层面的，想写一个模拟 http 请求的，直接将获取到的 cookies 与原有的 cookie 合并即可。我那时候的代码就是这样：

```js
let newCookie = res.header['set-cookie']
  ? res.header['set-cookie']
      .map((a) => {
        return a.split(';')[0]
      })
      .join('; ')
  : ''

// mergeCookie 就是将两者cookie 拼接而成
let newCookies = mergeCookie(cookies, newCookie)

res[cookie] = newCookies
return res
```

然后返回响应中携带 res.cookies 即可，下次请求的时候再将其在带上。

如果只是，利用 nodejs 来实现类似爬虫，模拟登录，然后利用登录后的 cookie，来获取用户信息。如果不希望手动处理 cookies 的话，我其实还是推荐一个 http 模块，superagent，做一些小爬虫和模拟请求挺好用的，就不做过多介绍了。不过由于 nestjs 中自带 axios 模块，加上需要转发 http 请求，于是我就自行封装了一个 axios。

## 总结

实际上，axios 会根据当前环境，来创建 xhr 对象（浏览器）还是 http 对象（nodejs），在我那时候都以为 axios 是两个共用的，初学 electron 的时候，一直卡在 http 请求的配置

```
  // `adapter` allows custom handling of requests which makes testing easier.
  // Return a promise and supply a valid response (see lib/adapters/README.md).
  adapter: function (config) {
    /* ... */
  },
```

在 axios 中也有这么一段配置，翻看了 lib/adapters 下目录我才瞬间醒悟过来，两者环境是不同的。

![image-20201210214055696](https://img.kuizuo.cn/image-20201210214055696.png)

就我使用而言，在浏览器环境下 axios 处理的特别好，允许设置拦截器处理请求与响应，但在 nodejs 下在处理模拟请求确实不如 Python 的 request 模块，奈何 axios 最大的便携就是能直接在浏览器中，尤大推荐的 http 请求库也是 axios。

实际上还涉及到了 nodejs 中转发请求的，再给自己留一个坑。

在写这篇文章的时候，我其实都没读过 axios 的源码，说实话，那时候遇到问题，就不应该愚昧的去搜索，去不断尝试，有时候直接通过翻看底层代码，可以一目了然自己所面临问题的解决方式。
