---
slug: sse-server-send-event
title: SSE 服务器发送事件
date: 2022-03-16
authors: kuizuo
tags: [http]
keywords: [http]
---

<!-- truncate -->

先放一张 gif 图展示下效果

![sse](https://img.kuizuo.cn/sse.gif)

实现上面这个效果之前，先补充点前置知识

众所周知，在 HTTP 协议中，服务器无法向浏览器推送信息，可以使用 WebSocket 来实现两者双向通信。而在这里所要介绍的是 SSE（Server-Sent Events），在浏览器向服务器请求后，服务器每隔一段时间向客户端发送流数据（是单向的），来实现接收服务器的数据，例如在线视频播放，和像上面所演示的效果。

![img](https://www.ruanyifeng.com/blogimg/asset/2017/bg2017052702.jpg)

关于 SSE 标准文档 [MDN 文档](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events)

### 优点

- SSE 使用 HTTP 协议，现有的服务器软件都支持。WebSocket 是一个独立协议。
- SSE 属于轻量级，使用简单；WebSocket 协议相对复杂。
- SSE 默认支持断线重连，WebSocket 需要自己实现。
- SSE 一般只用来传送文本，二进制数据需要编码后传送，WebSocket 默认支持传送二进制数据。
- SSE 支持自定义发送的消息类型。

## 服务器实现

### 数据格式

服务器向浏览器发送的 SSE 数据，必须是 UTF-8 编码的文本，具有如下的 HTTP 头信息。

```http
Content-Type: text/event-stream; charset=utf-8
Cache-Control: no-cache
Connection: keep-alive
```

使用 Node 实现的代码如下

```javascript
var http = require('http')

http
  .createServer(function (req, res) {
    var fileName = '.' + req.url

    if (fileName === './stream') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        'Access-Control-Allow-Origin': '*',
      })
      res.write('retry: 10000\n')
      res.write('event: connecttime\n')
      res.write('data: ' + new Date() + '\n\n')
      res.write('data: ' + new Date() + '\n\n')

      interval = setInterval(function () {
        res.write('data: ' + new Date() + '\n\n')
      }, 1000)

      req.connection.addListener(
        'close',
        function () {
          clearInterval(interval)
        },
        false,
      )
    }
  })
  .listen(8844, '127.0.0.1')
```

通过 node server.js 运行服务端，此时浏览器访问 http://127.0.0.1:8844/stream 得到的效果就是开头的 gif 所演示的。

## 客户端 API

像上面是直接向服务器请求，浏览器有`EventSource`对象，比如监听 SSE 连接，以及主动关闭 SSE 连接，具体的演示代码如下

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width" />
    <title>JS Bin</title>
  </head>
  <body>
    <div id="example"></div>
    <script>
      var source = new EventSource('http://127.0.0.1:8844/stream')
      var div = document.getElementById('example')

      source.onopen = function (event) {
        div.innerHTML += '<p>Connection open ...</p>'
      }

      source.onerror = function (event) {
        div.innerHTML += '<p>Connection close.</p>'
      }

      source.addEventListener(
        'connecttime',
        function (event) {
          div.innerHTML += '<p>Start time: ' + event.data + '</p>'
        },
        false,
      )

      source.onmessage = function (event) {
        div.innerHTML += '<p>Ping: ' + event.data + '</p>'
      }
    </script>
  </body>
</html>
```

并且由于是调用浏览器 API，在开发者工具的网络面板上还能看到对应的 EventStream，像下面这样

![image-20220316134321431](https://img.kuizuo.cn/image-20220316134321431.png)

## 参考链接

> [使用服务器发送事件 - Web API 接口参考 | MDN (mozilla.org)](https://developer.mozilla.org/zh-CN/docs/Web/API/Server-sent_events/Using_server-sent_events)
>
> [Server-Sent Events 教程 - 阮一峰的网络日志 (ruanyifeng.com)](https://www.ruanyifeng.com/blog/2017/05/server-sent_events.html)
