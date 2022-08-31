---
id: go-send-http-request
slug: /go-send-http-request
title: Go发送http请求
date: 2022-05-22
authors: kuizuo
tags: [go, http]
keywords: [go, http]
---

<!-- truncate -->

## Get 请求

```go
import (
  "fmt"
  "io/ioutil"
  "net/http"
)

func main() {
  resp, err := http.Get("http://127.0.0.1:5000/api/test")

  if err != nil {
    panic(err)

  }
  defer resp.Body.Close()

  s, _ := ioutil.ReadAll(resp.Body)

  fmt.Println(resp.StatusCode)
  fmt.Println(string(s))
}
```

可以发现上面的例子中还需要对**响应体**进行读取，如果每条请求都需要如此操作的话，代码逻辑将会十分臃肿，一般都需要自行封装。而事实上大部分的编程语言的 http 请求库(包)都不会过度封装，一般都需要用户自行封装或使用第三方请求库。

当然这里肯定毫不犹豫的选择第三方库，后文会推荐几个，以及一些使用代码，这里还需要使用原生 http 库发送 Post 请求

## Post 请求

### 发送 querystring

```go
import (
  "fmt"
  "io/ioutil"
  "net/http"
  "strings"
)

func main() {
  payload := strings.NewReader("foo=1&bar=2")

  resp, err := http.Post("http://127.0.0.1:5000/api/test", "application/x-www-form-urlencoded", payload)

  if err != nil {
    panic(err)
  }
  defer resp.Body.Close()

  s, _ := ioutil.ReadAll(resp.Body)

  fmt.Println(resp.StatusCode)
  fmt.Println(string(s))
}

```

此外还可以使用 http.PostForm（省略读取响应代码）

```go
import (
  "net/http"
  "net/url"
)

func main() {
  payload := url.Values{"foo": {"1"}, "bar": {"2"}}

  resp, err := http.PostForm("http://127.0.0.1:5000/api/test", payload)
}

```

### 发送 json

```go
import (
  "fmt"
  "net/http"
  "strings"
)

func main() {
  payload := strings.NewReader(`{"name":"kuizuo"}`)

  req, _ := http.NewRequest("POST", "http://127.0.0.1:5000/api/test", payload)

  req.Header.Add("Content-Type", "application/json")

  res, _ := http.DefaultClient.Do(req)
  fmt.Println(res)
}

```

至于其他方法就不做演示，不对其封装将十分难用，日常开发主要还是使用第三方 http 请求库。

## HTTP 请求库

[valyala/fasthttp: Fast HTTP package for Go. Tuned for high performance. Zero memory allocations in hot paths. Up to 10x faster than net/http (github.com)](https://github.com/valyala/fasthttp)

[go-resty/resty: Simple HTTP and REST client library for Go (github.com)](https://github.com/go-resty/resty)

[imroc/req: Simple Go HTTP client with Black Magic (github.com)](https://github.com/imroc/req)

[levigross/grequests: A Go "clone" of the great and famous Requests library (github.com)](https://github.com/levigross/grequests)

整合了几个 Github 上所开源的 http 请求库，更多 http 库可在[http-client · GitHub Topics](https://github.com/topics/http-client?l=go)上查看 ，这里对其进行简单优点介绍，以及个人的选择。

- [fasthttp](https://github.com/valyala/fasthttp) 号称比 net/http 快 10 倍的 http 包，并且 star 数最多的。
- [resty](https://github.com/go-resty/resty#usage) 一个链式调用的请求库。
- [Req](https://req.cool/) 与 resty 使用相似，并且提供非常友好的使用文档（有中文）。
- [grequests](https://github.com/levigross/grequests) go 语言版的 python requests。

如果使用过 python requests 库，那么可以毫不犹豫的选择 grequests。很显然，我使用过 requests，所以也就毫不犹豫的选择 grequests。

## grequests

这里写一个模拟登录的例子

```go

import (
  "fmt"

  "github.com/levigross/grequests"
)

type Demo struct {
  Session *grequests.Session
  User    User
}

type User struct {
  Username string
  Password string
}

type Result struct {
  Code int    `json:"code"`
  Msg  string `json:"msg"`
}

func (dm *Demo) login() string {

  resp, err := dm.Session.Post("http://127.0.0.1:5000/api/login",
    &grequests.RequestOptions{
      Data: map[string]string{
        "username": dm.User.Username,
        "password": dm.User.Password,
      },
      Headers: map[string]string{
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
      },
    })

  var result Result
  resp.JSON(&result)

  if err == nil && result.Code == 200 {
    return "登录成功"
  }

  return result.Msg
}

func main() {
  var session = grequests.NewSession(nil)
  dm := Demo{
    Session: session,
    User: User{
      Username: "kuizuo",
      Password: "a123456",
    },
  }
  loginResult := dm.login()
  fmt.Println(loginResult)
  // TODO:
}

```

因为 go 中没有类的概念，所以想要实现“类”，就得在 `func` 和方法名之间添加方法所属的类型声明（有的地方将其称之为接收者声明）

也就是`func (dm *Demo) login() string {` 中的`(dm *Demo)` 其中这里的 Demo 根据实际需求进行更换，并且前面的 dm 无法更名为 this 或 self。

如果想发送 json 请求的话，grequests 写法也挺简单的，只需要将 Data 替换为 JSON（协议头会自动添加 Content-Type: application/json），如下

```go
  resp, err := dm.Session.Post("http://127.0.0.1:5000/api/login",
    &grequests.RequestOptions{
      JSON: map[string]string{
        "username": dm.User.Username,
        "password": dm.User.Password,
      },
    })
```

## 总结

相比 js 和 python 来写 http 请求，由于 go 中没有类的概念（即无 class 关键字），所以只能利用**自定义结构体**来实现这样功能，并且在代码写法上也不算优雅。综合考虑的情况下，还是优选 js 和 python 来复现 http 协议。
