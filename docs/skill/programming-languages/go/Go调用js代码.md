---
id: go-call-js
slug: /go-call-js
title: Go调用js代码
date: 2022-05-22
authors: kuizuo
tags: [go, javascript]
keywords: [go, javascript]
---

<!-- truncate -->

## 运行 js 代码

```go
import (
  "fmt"

  "github.com/robertkrimen/otto"
)

func main() {
  vm := otto.New()
  result, _ := vm.Run(`
      foo = 1 + 2
      console.log(foo)
      result = foo;
  `)
  fmt.Println(result) // 4
}
```

## 调用函数

```go
func main() {
  vm := otto.New()
  vm.Run(`
  function hello(name){
      console.log('hello ' + name)
      return 'OK'
  }
`)

  ret, _ := vm.Call("hello", nil, "kuizuo")
  fmt.Println(ret)
}

```

这里以 go 调用 js 的 CryptoJS 来实现加密演示。

```go
func main() {
  bytes, _ := ioutil.ReadFile("md5.js")
  vm := otto.New()
  vm.Run(string(bytes))

  ret, _ := vm.Call("MD5", nil, "a123456")
  fmt.Println(ret)
}
```

## 封装成 go 函数

不过这样写法不方便，可以将其封装为一个 go 函数来调用。

```go
import (
  "fmt"
  "io/ioutil"

  "github.com/robertkrimen/otto"
)

var vm = otto.New()

func initJs() {
  bytes, _ := ioutil.ReadFile("md5.js")
  vm.Run(string(bytes))
}

func md5(content string) string {
  ret, err := vm.Call("MD5", nil, content)
  if err != nil {
    return ""
  }
  return ret.String()
}

func main() {
  initJs()
  result := md5("a123456")
  fmt.Println(result)
}

```
