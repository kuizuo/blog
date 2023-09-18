---
id: go-concurrent
slug: /go-concurrent
title: Go并发
date: 2022-05-22
authors: kuizuo
tags: [go]
keywords: [go]
---

Go 语言的并发是基于 `goroutine` 的，`goroutine` 类似于线程，但并非线程。可以将 `goroutine` 理解为一种虚拟线程。Go 语言运行时会参与调度 `goroutine`，并将 `goroutine` 合理地分配到每个 CPU 中，最大限度地使用 CPU 性能。开启一个 goroutine 的消耗非常小（大约 2KB 的内存），你可以轻松创建数百万个`goroutine`。

<!-- truncate -->

## goroutine

goroutine 语法格式：

```text
go 函数名( 参数列表 )
```

演示代码如下

```go
import (
  "fmt"
  "time"
)

func say(s string) {
  for i := 0; i < 3; i++ {
    time.Sleep(100 * time.Millisecond)
    fmt.Println(s)
  }
}

func main() {
  go say("world")
  say("hello")
  fmt.Println("over!")
}
```

执行上面代码将会输出

```go
hello
world
world
hello
hello
over!
```

其中 hello 与 world 每次执行顺序都不一致，甚至有时候 world 会少输出一遍，或是 world 将会在 over! 后输出。因为此时的`go say("world")` 不在是主线程中执行，而是创建一个 goroutine 去执行。可以认为`go say("world")`就相当于 js 中的`await say("world")` 但 js 是单线程基于事件循环机制来实现的，所以两者还是有着一定的区别。

## 等待 goroutine 执行完成

可以发现 say("hello") 实际上也是在等待执行，如果将 say("hello")注释掉，再次执行，将只会输出 over!。原因很简单，因为主线程已经结束了，程序自然就结束了，goroutine 的执行也就不是程序的重点。

所以有时候需要等待 goroutine 执行完成，最直接的方法就是通过 time.Sleep 函数，或执行时间较长的函数来等待，但实际执行中并不知道应该等待多长时间，很显然这种方式并不是特别好。

## sync 包

Golang 官方在 sync 包中提供了 WaitGroup 类型来解决这个问题，下面是其简单的演示例子。

```go
import (
  "fmt"
  "sync"
  "time"
)

func say(s string, wg *sync.WaitGroup) {
  defer wg.Done()

  for i := 0; i < 3; i++ {
    time.Sleep(100 * time.Millisecond)
    fmt.Println(s)
  }
}

func main() {
  var wg sync.WaitGroup
  wg.Add(2)
  say("hello", &wg)
  say("world", &wg)

  wg.Wait()
  fmt.Println("over!")
}
```

将会像同步输出一样，输出结果

```go
hello
hello
hello
world
world
world
over!
```

使用方法可以总结为下面几点：

1. 创建一个 WaitGroup 实例，比如名称为：wg
2. 调用 wg.Add(n)，其中 n 是等待的 goroutine 的数量
3. 在每个 goroutine 运行的函数中执行 defer wg.Done()
4. 调用 wg.Wait() 阻塞主逻辑

## 通道（channel）

如果说 goroutine 是 Go 语言程序的并发体的话，那么 channels 则是它们之间的通信机制。一个 channel 是一个通信机制，它可以让一个 goroutine 通过它给另一个 goroutine 发送值信息。每个 channel 都有一个特殊的类型，也就是 channels 可发送数据的类型。一个可以发送 int 类型数据的 channel 一般写为 chan int。

使用内置的 make 函数，我们可以创建一个 channel：

```go
ch := make(chan 元素类型, [缓冲大小])
```

先展示一个简单的代码例子

```go
import "fmt"

func sum(s []int, c chan int) {
  sum := 0
  for _, v := range s {
    sum += v
  }
  c <- sum // 把 sum 发送到通道 c
}

func main() {
  s := []int{1, 2, 3, 4, 5}

  c := make(chan int)
  go sum(s[:len(s)/2], c)
  go sum(s[len(s)/2:], c)
  x, y := <-c, <-c // 从通道 c 中接收

  close(c) // 关闭通道

  fmt.Println(x, y, x+y)
}
```

将会输出 12 3 15

关闭通道不是必须的，但关闭后的通道有以下特点：

1.对一个关闭的通道再发送值就会导致 panic。

2.对一个关闭的通道进行接收会一直获取值直到通道为空。

3.对一个关闭的并且没有值的通道执行接收操作会得到对应类型的零值。

4.关闭一个已经关闭的通道会导致 panic。

## 实例

一个深度遍历的代码例子，具体可看 [示例: 并发的 Web 爬虫 · Go 语言圣经 (studygolang.com)](https://books.studygolang.com/gopl-zh/ch8/ch8-06.html)

```go
import (
  "fmt"
  "log"
  "net/http"

  "golang.org/x/net/html"
)

func crawl(url string) []string {
  fmt.Println(url)
  list, err := Extract(url)
  if err != nil {
    log.Print(err)
  }
  return list
}

func Extract(url string) ([]string, error) {
  resp, err := http.Get(url)
  if err != nil {
    return nil, err
  }
  if resp.StatusCode != http.StatusOK {
    resp.Body.Close()
    return nil, fmt.Errorf("getting %s: %s", url, resp.Status)
  }

  doc, err := html.Parse(resp.Body)
  resp.Body.Close()
  if err != nil {
    return nil, fmt.Errorf("parsing %s as HTML: %v", url, err)
  }

  var links []string
  visitNode := func(n *html.Node) {
    if n.Type == html.ElementNode && n.Data == "a" {
      for _, a := range n.Attr {
        if a.Key != "href" {
          continue
        }
        link, err := resp.Request.URL.Parse(a.Val)
        if err != nil {
          continue // ignore bad URLs
        }
        links = append(links, link.String())
      }
    }
  }
  forEachNode(doc, visitNode, nil)
  return links, nil
}

func forEachNode(n *html.Node, pre, post func(n *html.Node)) {
  if pre != nil {
    pre(n)
  }
  for c := n.FirstChild; c != nil; c = c.NextSibling {
    forEachNode(c, pre, post)
  }
  if post != nil {
    post(n)
  }
}

func main() {
  worklist := make(chan []string)

  go func() { worklist <- []string{"http://gopl.io/"} }()

  // Crawl the web concurrently.
  seen := make(map[string]bool)
  for list := range worklist {
    for _, link := range list {
      if !seen[link] {
        seen[link] = true
        go func(link string) {
          worklist <- crawl(link)
        }(link)
      }
    }
  }
}

```

## 参考文章

[Goroutines 和 Channels · Go 语言圣经 (studygolang.com)](https://books.studygolang.com/gopl-zh/ch8/ch8.html)

[https://www.cnblogs.com/sparkdev/p/10917536.html](https://www.cnblogs.com/sparkdev/p/10917536.html)
