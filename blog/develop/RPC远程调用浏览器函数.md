---
slug: remote-call-browser-function
title: RPC远程调用浏览器函数
date: 2021-10-09
authors: kuizuo
tags: [javascript, rpc, browser]
keywords: [javascript, rpc, browser]
---

早闻 RPC（Remote Procedure Call）远程过程调用，这一词了，应该是在安卓逆向的时候听闻的，当时吹嘘的意思是这样的，通过另一个远端服务器来调用安卓代码中的函数，并将执行后的结果返回。比如有一个加密算法，如果要实现脱机（脱离当前环境）运行的话，就需要扣除相对应的代码，补齐对应的环境（模块，上下文，语言），然而要在补齐该加密算法的环境可不好实现，而通过 RPC 则可以免除扣代码，通过数据通信来达到远程调用的目的，听起来是挺牛逼的，实际上也确实挺骚的。这里我将以浏览器与本地搭建一个 websocket 来实现调用浏览器内的函数。

<!-- truncate -->

## 算法例子

这里我所采用的是百度登录的密码加密算法，具体逆向实现就不细写了，借用视频教程[志远 2021 全新 js 逆向 RPC](https://www.bilibili.com/video/BV1Kh411r7uR?p=36)

通过关键词`password:` 便可找到对应的加密地点，找到加密调用的函数所出现的位置（loginv5.js 8944 行），发现通过调用`e.RSA.encrypt(s)`（其中 s 为明文 `a123456`），便可得到加密后的结果。

![image-20211008042148653](https://img.kuizuo.cn/image-20211008042148653.png)

![image-20211008041300534](https://img.kuizuo.cn/image-20211008041300534.png)

```
e.RSA.encrypt(s)
'Zhge9q9jkiMA0UTfHxwNeyafnuUG8rcAh/gKfQpZiOQq8EYI/tJO83lKr52c4Im3cew3wVcINf2jEGEqH5EimnMI3g6eOjcdqduGyqynA4JjMJ0wltGdL8VUTTJsknsHUQlJXHOm/7zqx4NaBvOzhWzdDBk5cAOJ2DXgPaqoygg='
```

按照往常的做法，需要将`e.RSA.encrypt(s)`所用的代码处单独抠出来，放在 V8 引擎上测试或使用现有的加密库 如 CryptoJS，找到对应的密钥来进行加密。不过这里使用 RPC 来实现该算法的调用。

## 实现

目前调用的环境有了（浏览器环境），只要我们这个浏览器不停止（使用无头浏览器运行），控制台便能一直输出我们想要的加密后结果。所以要实现的目的很简单，就是其他窗口（指其他语言所实现的程序），能远程调用`e.RSA.encrypt(s)`并将结果输出到其他窗口。

那么就需要建立通信协议了，这里我所采用的是浏览器自带的 Websocket 客户端与 Nodejs 搭建的 Websocket 服务端来进行通信，众所周知 HTTP 请求是无法双向传输的。所以使用 websocket 这样服务端就可以主动向浏览器发送请求，同时 websocket 在当前这个环境下好实现。

### Nodejs 实现 Websocket 服务端

#### 安装 ws 模块

```sh
npm install ws -S
npm install @types/ws -D
```

这里之所以选 ws，是因为 ws 对于 Websocket 协议而已，实现方便，且速度最快，并且浏览器可以通过`let ws = new Websocket()`来创建客户端直接连接，而使用 socket.io 的话，浏览器则需要载入 socket.io 客户端文件，繁琐。

#### 代码例子

```javascript title="server.js"
import WebSocket, { WebSocketServer } from 'ws'

let ws = new WebSocketServer({
  port: 8080,
})

ws.on('connection', (socket) => {
  function message(msg) {
    console.log('接受到的msg: ' + msg)
    socket.send('我接受到你的数据: ' + msg)
  }

  socket.on('message', message)
})
```

使用 WebSocket 在线测试网站[websocket 在线测试 (websocket-test.com)](http://www.websocket-test.com/)

测试结果如下

![image-20211008043925753](https://img.kuizuo.cn/image-20211008043925753.png)

上面代码写的很简陋，尤其是数据交互的地方，这里可以使用 json 来改进一下。像这样，至于为啥用 try 是防止 json 数据不对导致解析错误（具体代码就不解读了）

```javascript title="server.js"
import WebSocket, { WebSocketServer } from 'ws'

let ws = new WebSocketServer({ port: 8080 })

ws.on('connection', (socket) => {
  console.log('有人连接了')
  function message(data) {
    try {
      let json = JSON.parse(data) // data: {"type":"callbackPasswordEnc","value":"a123456"}
      let { type, value } = json
      switch (type) {
        case 'callbackPasswordEnc':
          // doSomething()
          console.log('得到的加密密文为:' + value)
          break
      }
    } catch (error) {
      console.error(error)
    }
  }

  socket.on('message', message)

  // 浏览器通信1秒后向浏览器调用加密算法
  setTimeout(() => {
    let jsonStr = JSON.stringify({
      type: 'getPasswordEnc',
      value: 'a123456',
    })
    socket.send(jsonStr)
  }, 1000)
})
```

### 浏览器实现 websocket

既然要实现我们的代码，那么就需要将我们的代码注入到原来的代码上，这里我使用的是 Chrome 的开发者工具中的覆盖功能，选择一个本地文件夹，并允许权限。

![image-20211008054918531](https://img.kuizuo.cn/image-20211008054918531.png)

选择要替换代码的文件，选择保存以备替换（前提得开启覆盖）

![image-20211008055032125](https://img.kuizuo.cn/image-20211008055032125.png)

接着在覆盖中找到文件，找到加密的代码块，添加如下代码

```javascript title="browser.js"
!(function () {
  let url = 'ws://127.0.0.1:8080'
  let ws = new WebSocket(url)

  // 浏览器连接后告诉服务端是浏览器
  ws.onopen = function (event) {
    ws.send(JSON.stringify({ type: 'isBrowser', value: true }))
  }

  ws.onmessage = function (event) {
    let json = JSON.parse(event.data)
    let { type, value } = json
    switch (type) {
      case 'getPasswordEnc':
        let passwordEnc = e.RSA.encrypt(value)
        let jsonStr = JSON.stringify({
          type: 'callbackPasswordEnc',
          value: passwordEnc,
        })
        console.log(jsonStr)
        ws.send(jsonStr)
        break
    }
  }
})()
```

![image-20211008201809446](https://img.kuizuo.cn/image-20211008201809446.png)

然后就是最关键的地方了，触发加密函数，并将结果返回。触发加密函数只需要向浏览器发送指定数据`{"type":"getPasswordEnc","value":"a123456"}`，浏览器接受到对应的类型与数据，便调用相应的函数，并将结果`{"type":"callbackPasswordEnc","value":"FM6SK3XiL5X0RF9NZi7qhIsu7Pd46mfKnn6YkWUNSGrJO+XXhiXyoG8huaqQW4BnmYuo0JVVQj28C+BK/r6NTNbLcV4gMSREB2hYU/oIYedCJsZ9sbZQ89p1aI9kVcDeRlXBhjNUxkcS9Rh+vKzyNApwpbPcAuGTCSZhKst8vVo="}`返回即可。

服务端的效果如下图

![image-20211008204247104](https://img.kuizuo.cn/image-20211008204247104.png)

## 优化执行流程

实现是实现了，但是代码貌似很不优雅，甚至有点别扭。按理来说因为是浏览器作为 websocket 服务端，我们作为客户端，客户端向服务器获取数据才合理，但在这里浏览器当不了 websocket 服务端这个角色，所以只能使用如此别扭的方式来调用。像上面例子的话，如果我的程序要实现一个某度登录的话，那么我这个程序就需要搭建一个 ws 服务器来进行两者的通信，有没有好的办法又不太依赖于 ws 服务端，就像 http 那样，程序只需要发送一个请求，给定类型和数值进行加密处理后返回即可。于是我处理的思路是这样的。

## 思路

我的做法是将 websocket 服务端当个中转站，而浏览器的 websocket 客户端作为一个加密算法的服务，再添加一个登录算法实现的客户端简称为用户调用的，所以现在一共有三份代码（websocket 服务端，浏览器端，用户调用端）。这里我还是以 nodejs 为例。

### 浏览器端

浏览器 websocket 客户端的代码，在初次连接的时候，告诉 websocket 服务端是不是浏览器。并将于浏览器连接的 socket 句柄存入全局对象，以便用户获取加密参数的时候向浏览器调用。

```javascript title="browser.js"
ws.onopen = function (event) {
  ws.send(JSON.stringify({ type: 'isBrowser', value: true }))
}
```

### 用户调用端

```javascript title="client.js"
import WebSocket from 'ws'

async function getPasswordEnc(password) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket('ws://127.0.0.1:8080')

    ws.on('open', () => {
      let jsonStr = JSON.stringify({
        type: 'getPasswordEnc',
        value: password,
      })
      ws.send(jsonStr)
    })

    ws.on('message', (message) => {
      let json = JSON.parse(message)
      let { type, value } = json
      switch (type) {
        case 'callbackPasswordEnc':
          ws.close()
          resolve(value)
          break
      }
    })
  })
}

async function run() {
  let passwordEnc = await getPasswordEnc('a123456')
  console.log(passwordEnc)
}

run()
```

这里对代码进行解读一下，我自行封装了一个函数，其中函数返回的是一个 Promise 对象，值则是对应的加密后的密文。如果我这边不采用 promise 来编写的话，那么获取到的数据将十分不好返回给我们的主线程。这里对于 js 的 Promise 使用需要花费点时间去理解。总而言之，通过 promise，以及 async await 语法糖，能很轻松的等待 websocket 连接与接收数据。但还是用 websocket 协议

### websocket 服务端

同时 websocket 服务端肯定要新增一个类型用于判断是登录算法实现的客户端。同时又新的用户要调用，所以这里使用了 uuid 这个模块来生成唯一的用户 id，同时还定义一个变量 clients 记录所连接过的用户（包括浏览器），完整代码如下

```javascript title="server.js"
import WebSocket, { WebSocketServer } from 'ws'
import { v4 as uuidv4 } from 'uuid'

let ws = new WebSocketServer({ port: 8080 })

let browserWebsocket = null
let clients = []

ws.on('connection', (socket) => {
  let client_id = uuidv4()
  clients.push({
    id: client_id,
    socket: socket,
  })

  socket.on('close', () => {
    for (let i = 0; i < clients.length; i++) {
      if (clients[i].id == client_id) {
        clients.splice(i, 1)
        break
      }
    }
  })

  socket.on('message', (message) => {
    try {
      let json = JSON.parse(message)
      let { id, type, value } = json
      switch (type) {
        case 'isBrowser':
          if (value) {
            browserWebsocket = socket
          }
          console.log('浏览器已初始化')
          break

        // 发送给浏览器 让浏览器来调用并返回
        case 'callbackPasswordEnc':
          // 根据id找到调用用户的socket,并向该用户发送加密后的密文
          let temp_socket = clients.find((c) => c.id == id).socket

          temp_socket.send(message)
          break
        // 用户发送过来要加密的明文
        case 'getPasswordEnc':
          let jsonStr = JSON.stringify({
            id: client_id,
            type: type,
            value: value,
          })

          // 这里一定要是浏览器的websocket句柄发送，才能调用
          browserWebsocket.send(jsonStr)
          break
      }
    } catch (error) {
      console.log(error.message)
    }
  })
})
```

最终演示效果如下视频（浏览器代码是提前注入进去的）

<video width="800px" height="450px" controls="controls" >
<source id="mp4" src="https://img.kuizuo.cn/rpc.mp4" type="video/mp4" />
</video >

其实还是一些是要完善的，这里的 Websocket 只是实现了连接，还有心跳包异常断开，浏览器异常关闭导致 websocket 断开无法调用函数等等，以及浏览器的代码还需要手动注入很不优化，后续如果使用 Chrome 插件开发一个实现注入 js 代码的功能也许会好一些。（正准备编写 Chrome 插件）

## HTTP 协议调用实现

但是，以上都是基于 WebSocket 协议，就连用户端调用也是，然而用户调用没必要保持长连接且不利于调用（相对一些语言而言），有没有能直接使用 http 协议，通过 POST 请求来实现获取参数，这才是我所要实现的。

其实要实现也很简单，我只要把用户调用的 `getPasswordEnc` 这个函数 弄到 node 创建的一个 http 服务端就行了，我这里的做法也是如此。像下面这样

```javascript title="server_http.js"
async function getPasswordEnc(password) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket('ws://127.0.0.1:8080')

    ws.on('open', () => {
      let jsonStr = JSON.stringify({
        type: 'getPasswordEnc',
        value: password,
      })
      ws.send(jsonStr)
    })

    ws.on('message', (message) => {
      let json = JSON.parse(message)
      let { type, value } = json
      switch (type) {
        case 'callbackPasswordEnc':
          ws.close()
          resolve(value)
          break
      }
    })
  })
}

// 创建http服务
const app = http.createServer(async (request, response) => {
  let { pathname, query } = url.parse(request.url, true)

  if (pathname == '/getPasswordEnc') {
    let passwordEnc = await getPasswordEnc(query.password)
    response.end(passwordEnc)
  }
})

app.listen(8000, () => {
  console.log(`服务已运行 http://127.0.0.1:8000/`)
})
```

发送 GET 请求 URL 为 http://127.0.0.1:8000/getPasswordEnc?password=a123456 实现效果如图

![image-20211009040704534](https://img.kuizuo.cn/image-20211009040704534.png)

对于用户调用来说相对友好了不少（其实是很好），不用在创建 websocket 客户端，只需要发送 HTTP 请求（GET 或 POST），不过我这边使用的是 Node 自带的 http 模块来搭建的一个 http 服务器，实际使用中将会采用 express 来编写路由提高开发效率和代码可读性，这里只是作为演示。

至于说我为什么要在 http 内在新建一个 ws 客户端，主要原因还是 websocket 服务端向浏览器发送调用的算法，但只能在 websocket 服务端中的通过 onmessage 接受，无法在 http 服务端接受到，就别说向用户端返回了。这里其实只是不让用户来进行连接 websocket，而是我们本地（服务器）在接受到 getPasswordEnc 请求，复现了一遍上面用户连接 websocket 的例子，并将其转为 http 请求返回给用户而已。

**其实也就是多了一个调用的 HTTP 服务器，而这里将 http 服务器与 websocket 服务器写到一起而已**

## 代码地址

https://github.com/kuizuo/rpc-browser.git

运行方式请查看 README.md
