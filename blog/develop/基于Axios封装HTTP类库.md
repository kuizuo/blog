---
slug: axios-http-class-library
title: 基于Axios封装HTTP类库
date: 2021-08-26
authors: kuizuo
tags: [node, http, axios]
keywords: [node, http, axios]
description: 基于 Axios 封装 HTTP 类库，并发布到 npm 仓库中
---

<!-- truncate -->

一个基于 Axios 封装 HTTP 类库

源代码 [kz-http](https://github.com/kuizuo/kz-http)

## 使用方法

npm 安装

```sh
npm i kz-http -S
```

### 请求

```javascript
import Http from 'kz-http'

let http = new Http()

http.get('https://www.example.com').then((res) => {
  console.log(res)
})
```

## 能解决什么

axios 明明那么好用，为啥又要基于 axios 重新造一个轮子。首先不得否认的是 axios 确实好用，Github 能斩获近 90k 的 star，且基本已成为前端作为数据交互的必备工具。但是它对我所使用的环境下还是存在一定的问题，也就是我为什么要重新造一个轮子。

### Node 环境下无法自动封装 Set-Cookie

如果 axios 是运行在浏览器那还好说，就算你无论怎么请求，浏览器都会自动将你的所有请求中的响应包含 set-cookie 参数，提供给下一次同域下的请求。但是，Node 环境并不是浏览器环境，在 Node 环境中运行并不会自动保存 Cookie，还需要手动保存，并将 Cookie 添加至协议头给下一个请求。（如果是 Python 的话，request 有个 session 方法可以自动保存 cookie，十分方便）

一开始我是自行封装，将响应中的 set-cookie 全都存在实例对象 http.cookies 上，但封装的不彻底，如果有的网站

间请求存在跨域，那么会将携带不该属于该域下的 Cookies。于是乎，我在 github 仓库找到了一个库可达到我的目的

[3846masa/axios-cookiejar-support: Add tough-cookie support to axios. (github.com)](https://github.com/3846masa/axios-cookiejar-support)

具体安装可以直接点击链接查看，这里贴下我**之前**的封装代码

```javascript
const tough = require('tough-cookie');
const axiosCookieJarSupport = require('axios-cookiejar-support').default;
axiosCookieJarSupport(axios);

class Http {
  public cookieJar;
  public instance: AxiosInstance;
  construction() {
    this.cookieJar = new tough.CookieJar(null, { allowSpecialUseDomain: true });
    this.instance = axios.create({
      jar: this.cookieJar,
      ignoreCookieErrors: false,
      withCredentials: true,
    });
  }
}
```

这样 axios 就会自动将响应中的 set-cookie 封装起来，供下次使用

但是正是由于导入了这个包，导致每次请求都需要处理，就会导致请求速度变慢，实测大约是在 100ms 左右，同时导入这个包之后，实例化的对象都将会携带对应 cookies，想要删除又得对应 Url，于是决定自行封装相关代码可查看 request 方法，实测下来大约有 10ms 左右的差距（前提都通过创建实例来请求），不过有个缺陷，我封装的代码是不进行同源判断的，如何你当前站点请求的是 api1.test.com，获取到 cookie1，那么请求 api2.test.com 的时候也会将 cookie1 携带，这边不做判断是不想在请求的时候耗费时间，比如网页与手机协议，一般这种情况建议实例化两个对象，如

```javascript
let http_api1 = new Http()
let http_api2 = new Http()
```

### 请求失败无法自动重试

在高并发的情况下，偶尔会出现请求超时，请求拒绝的情况，但是默认下 axios 是不支持自动重试请求的，不过可以借助插件`axios-retry`来达到这个目的

```javascript
const axiosRetry = require('axios-retry')

class Http {
  constructor(retryConfig?) {
    this.instance = axios.create()

    if (retryConfig) {
      axiosRetry(this.instance, {
        retries: retryConfig.retry, // 设置自动发送请求次数
        retryDelay: (retryCount) => {
          return retryCount * retryConfig.delay // 重复请求延迟
        },
        shouldResetTimeout: true, // 重置超时时间
        retryCondition: (error) => {
          if (axiosRetry.isNetworkOrIdempotentRequestError(error)) {
            return true
          }

          if (error.code == 'ECONNABORTED' && error.message.indexOf('timeout') != -1) {
            return true
          }
          if (['ECONNRESET', 'ETIMEDOUT'].includes(error.code)) {
            // , 'ENOTFOUND'
            return true
          }
          return false
        },
      })
    }
  }
}
```

这边判断重新发送请求条件是连接拒绝，连接重置，和连接超时的情况。

### 配置拦截器

有时候一个网站的协议是这样的，每一条 Post 都自动将所有参数进行拼接，然后进行 MD5 加密，并添加为 sign 参数，于是，不得不给每一条请求都进行这样的操作，那么有没有什么能在每次请求的时候，都自动的对参数进行 MD5 加密。如果使用过 axios 来配置过 JWT 效验，那自然就会熟悉给每条请求协议头都携带 JWT 数值。同样的，这里的加密例子同样使用，具体配置实例对象 http 的请求拦截器即可，如

```javascript
let http = new Http()

// axios实例instance是公开的
http.instance.interceptors.request.use(
  (config) => {
    // 执行每条请求都要处理的操作
    return config
  },
  (error) => {},
)
```

同样的，响应拦截器也同理，例如请求返回的响应都进行加密处理，那么就可以通过响应拦截器进行统一解密，这里就不做过多描述，具体场景具体分析。

### 封装一些常用方法

比如设置伪造 IP（setFakeIP），自动补全 referer 和 orgin 参数，禁止重定向等等，更详细的查看源码便可

## 发布 npm 包

如果要让别人使用的话，总不可能让他去下载源码然后编译吧，这里就借助 npm。

:::tip

在使用 npm 之前，请先使用`npm install -g npm@latest`升级为最新版，否则可能会提示 **ERR! 426 Upgrade Required**。原文 [The npm registry is deprecating TLS 1.0 and TLS 1.1 | The GitHub Blog](https://github.blog/2021-08-23-npm-registry-deprecating-tls-1-0-tls-1-1/)

:::

创建 npm 账号，创建 package.json

```json title="package.json"
{
  "name": "kz-http",
  "version": "0.1.0",
  "description": "An HTTP class library based on axios",
  "main": "dist/index.js",
  "scripts": {
    "build": "tsc"
  },
  "author": "kuizuo",
  "license": "ISC",
  "dependencies": {
    "axios": "^0.21.1",
    "axios-retry": "^3.1.9"
  },
  "devDependencies": {
    "typescript": "^4.3.5"
  },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/kuizuo/kz-http.git"
  },
  "keywords": ["node", "axios", "http"]
}
```

然后通过`npm login`登录 npm 账号，接着输入`npm publish --access public`发布即可

发布的是要注意以下几点

- 如果 npm 镜像必须是官方的，否则无法登录，镜像还原

  ```sh
  npm config set registry https://registry.npmjs.org/
  ```

  查看镜像配置地址

  ```sh
  npm get registry
  ```

- 如果包有重名，那么就无法发布，就必须要要改名

- 邮箱必须要验证（会接受一条下图邮箱），不然就会发布失败
  ![image-20210826212258752](https://img.kuizuo.cn/image-20210826212258752.png)

- **请勿随意删包，否则同名的包将需要 24 小时后才能发布（亲测）**

  > npm ERR! 403 403 Forbidden - PUT http://registry.npmjs.org/kz-http - kz-http cannot be republished until 24 hours have passed.

发布完成后，别人只需要通过`npm i kz-http`就可成功将模块下载至本地 node_modules 文件夹下
