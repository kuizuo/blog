---
id: python-spider-summary
slug: /python-spider-summary
title: Python爬虫总结
date: 2022-03-03
authors: kuizuo
tags: [python, node, http]
keywords: [python, node, http]
---

最近临时写了个 python 爬虫的例子（核心代码不开源），总结下这次编写过程中的一些相关知识点与注意事项，以一个用 nodejs 写爬虫的开发者的角度去看待与比对。

<!-- truncate -->

## 编码

在抓包与协议复现的时候，出现中文以及特殊符号免不了 url 编码，python 的编码可以使用内置库 urllib，同时也能指定编码格式。

gbk 编码中文是占 2 个字节，utf8 编码中文占 3 个字节

### url 编码

```python
from urllib.parse import urlencode, parse_qs, quote, unquote

quote("愧怍", encoding="gbk")
# %C0%A2%E2%F4
```

quot 还有一个 safe 参数，可以指定那个字符不进行 url 编码

```python
quote("?", safe=";/?:@&=+$,", encoding="utf8")
# ? 加了safe
# %3F 不加safe
```

解码操作与编码同理

```python
unquote("%C0%A2%E2%F4", encoding="gbk")
# 愧怍
```

如果编码格式错误，比如 gbk 编码用 utf8 解码将会变成不可见字符 ����，而用 utf8 编码用 gbk 解码，存在一个字节差，会输出成其他字符串，比如 `你好` 就会变成 `浣犲ソ`，代码 `unquote(quote("你好",encoding='utf8'), encoding="gbk")`

### URL 查询字符串

如果想构造一个 `a=1&b=2`的 url 查询字符串，使用文本拼接很不现实。urllib 提供 urlencode 与 parse_qs 可以在查询字符串与字典中切换

```python
urlencode({
    "username": '愧怍',
    "password": 'a123456'
})
# username=%E6%84%A7%E6%80%8D&password=a123456
```

也有 encoding 与 safe 参数，配置同 quote，就不演示了。

```python
parse_qs('a=1&a=2&b=2')
# {'a': ['1', '2'], 'b': ['3']}
```

将查询字符串转为 python 字典的话，值都是列表（应该是考虑可能会多个相同参数才这么设计）

小提一下，nodejs 中有个 querystring，方法 parse 与 stringify 与效果同理。

## 解构赋值

```python
a,b = [1,2]
print(a,b)

user = {
    "username": "kuizuo",
    "password": "a123456"
}
username, password = user.values()
print(username, password)

print(user.keys())
# dict_keys(['username', 'password'])
print(user.values())
# dict_values(['kuizuo', 'a123456'])
```

解构赋值没什么好说的，和 js 类似，只不过对字典的解构赋值的话，要取值则要调用 values()，取 key 的话默认不填，但是也可以调用 keys()

## 模板字符串

```python
user = 'kuizuo'
print(f'username: {user} age: {20+1}')
# username: kuizuo age: 21
```

同样{}中可以编写表达式，与 js 的模板字符串类似

如果是 python3.6 之前的话,则是用使用 string.format 方法（不常用，也不好用）

```python
"username: {} age: {}".format("愧怍", 18)
```

而 js 中的模板字符串则是使用反引号`和${}，像下面这样

```javascript
user = 'kuizuo'
console.log(`username: ${user} age: ${20+1}`)
# username: kuizuo age: 21
```

## 字典

python 的字典与 js 的对象有些许相像，个人总体感觉没有 js 的对象灵活，演示如下

```python
user = { 'username':'kuizuo','password':'a123456' }
print(user['username'])
```

想要获取字典中的值，就需要写成`user['username']`，如果习惯了 js 的写法（比如我），就会习惯的写成`user.username`，这在 python 中将会报错，`AttributeError: 'dict' object has no attribute 'username'`，并且字典的 key 还需要使用引号进行包裹，如果是 js 的话，代码如下

```javascript
user = { username: 'kuizuo', password:'a123456'
console.log(user.username)
```

如果想在 key 中包裹引号也是可以的，省略引号相当于代码简洁，同时取值也可以像 python 中的`user['username']`来进行取值，相对灵活。

假设我想取 user 的 age 属性，但是 user 没有 age 属性，python 则是直接报错`KeyError: 'age'`，可以使用`user.get('age',20)`，如果没有 age 属性，则默认 20。而 js 是不会报错，则是会返回`undefiend`，如果想要默认值的话可以像这样，`user.age || 20`。毕竟 js 调用类的方法属性都是可以直接 `对象.属性` `对象.方法`，而 python 中是 `对象["属性"]` `对象.方法`，只能说各有各的优劣吧 。

不过 js 不确定是否有该属性的话，可以使用`?.`，比方`user?.age`，这样返回的`null`，而不是`undefiend`。

:::note 易错小结

获取字典属性使用 `字典['属性值']` 获取，key 需用引号包裹

:::

## 类

在写爬虫时，我都会将其封装成类，把一些核心的方法封装成类方法，比如登录，获取图片验证码等等

```python
class Demo():

    def __init__(self, user):
        self.user = user

    def get_img_code(self):
        pass

    def login(self):
        pass

    def get_xxx(self):
        pass
```

同样的，像 requests 的 session 也会将其封装在类属性下，但是我一开始的写法是

```python
class Demo():
    session = requests.Session()

    def __init__(self, user):
        self.user = user

```

导致我创建多个实例时

```python
demo1 = Demo()
demo2 = Demo()
```

demo1 与 demo2 的的 session 是相等的，经过百度，了解到这样定义的类属性相当于是共有属性，每个实例下获取到的都是同一个 session，如果将 session 放置在`__init__`下，每个实例的 session 就不相同

```python
class Demo():
    def __init__(self, user):
        self.session = requests.Session()
        self.user = user
```

其中 `__init__`相当于 js 中的 constructor，也就是构造函数了。

不过 python 的方法第一个参数都要是 self，像 js 或者 java 等一些面向对象的语言，不用特意声明 this，就可以直接使用 this 来调用自身属性与方法。而 python 则需要显式的声明 self。

[Python 为什么要保留显式的 self ？ - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/84546388)

:::note 易错小结

类共有属性与实例属性区别

:::

## 线程

python3 中线程操作可以使用 threading

```python
import threading

def func(name, sec):
    print('---开始---', name, '时间', ctime())
    sleep(sec)
    print('***结束***', name, '时间', ctime())

# 创建 Thread 实例
t1 = Thread(target=func, args=('第一个线程', 1))
t2 = Thread(target=func, args=('第二个线程', 2))

# 启动线程运行
t1.start()
t2.start()

# 等待所有线程执行完毕
t1.join()  # join() 等待线程终止，要不然一直挂起
t2.join()
```

### 多线程

如果要实现多线程的话，需要将 Thread 实例（线程句柄），保存到列表中，然后调用 join

```python
l = []

for i in range(10):  # 开启10个线程
    t = threading.Thread(target=func, args=('第'+str(i)+'个线程', i))
    t.start()
    l.append(t)

# 等待线程运行结束
for i in l:
    i.join()
```

### 锁

说到多线程，怎么可能不提到锁呢。

```python
import threading
from time import sleep

def func():
    global num
    sleep(1)
    lock.acquire() # 获取锁
    num = num+1
    print(num)
    lock.release() # 释放锁


lock = threading.Lock()
num = 0

for i in range(10):
    t = threading.Thread(target=func, args=())
    t.start()

```

获取与释放锁的操作可以使用 with 关键字来操作

```python
with lock:
	num = num+1
	print(num)
```

## 时间

### 计算两者时间间隔

```python
duringtime =  datetime.datetime.strptime('2022-03-02 16:16:16', "%Y-%m-%d %H:%M:%S") - datetime.datetime.now()
seconds = duringtime.seconds
```

### 定时任务

[8 种 Python 定时任务的解决方案 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/410388979)

## http 请求库

python 较为知名的 http 请求库无非就是 requests 了，但是 requests 不支持异步，在某些情况下，就只能等待上条请求结束，而异步请求则可以在发起一次请求后，在等待网站返回结果的时间里，可以继续发送更多请求。

此外还有 aiohttp、httpx，由于 httpx 又可以发送同步，也可以发送异步请求，号称新下一代网络请求库，并且基本与 requests 的代码重合度高，只需要改点对应关键词即可，这里所使用的时 httpx，并着重针对两者的区别进行测试。

### cookies

在 requests 中想要在下次使用上次响应中返回 cookies 十分简单，只需要设置实例化一个 session，然后使用 session 来发送后续的请求。在 requests 中是`session = requests.Session()`，而 httpx 则是`client = httpx.Client()`来代替

不过 httpx 则是有同步客户端与异步客户端，下面就是异步请求对的演示代码

```python
import asyncio
import httpx

async def main():
    async with httpx.AsyncClient() as client:  # 创建一个异步client
        r = await client.get('https://www.example.com/')
        print(r)

if __name__ == '__main__':
    asyncio.run(main())
```

获取请求的 cookies 也比较简单

request

```python
cookies_dict = requests.utils.dict_from_cookiejar(session.cookies)
```

httpx

```python
cookies_dict = dict(self.client.cookies)
```

### 协议头

在 http 请求中，少不了协议头的检测，比如说 Referer 检测来源链接是否符合要求，Content-Type 的请求体格式等等。但是如果在每条请求下都添加 headers 就略显代码繁杂，而且像很多公用的协议头 Origin，User-Agent 在全部的请求都是不变的，就可以使用`client.headers.update`设置成全局的协议头

```python
client.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edg/98.0.1108.62",
})
```

如果不设置的话，默认全局协议头如下

```python
Headers({'host': 'example.com', 'accept': '*/*', 'accept-encoding': 'gzip, deflate', 'connection': 'keep-alive', 'user-agent': 'python-httpx/0.22.0'})
```

### post 请求

post 请求主要有两种格式一个是查询字符串 `a=1&b=2`，另一个是 json 格式 `{"a": 1, "b": 2}`，下面为代码演示

查询字符串

```python
import httpx
data = {
    "username": "kuizuo",
    "password": "a123456"
}

httpx.post(
    url='http://example.com', data=data)
# 请求体 username=kuizuo&password=a123456
```

json

```python
import httpx
data = {
    "username": "kuizuo",
    "password": "a123456"
}

httpx.post(
    url='http://example.com', json=data)
# 请求体 {"username": "kuizuo", "password": "a123456"}
```

请求库将会自动将根据你所传入的字典，转成对应的格式，同时会携带对应`Content-Type`协议头`Content-Type: application/x-www-form-urlencoded` 与 `Content-Type: application/json`。所以就不需要使用

:::danger

要注意一点的时，如果 data 不是字典，而是字符串 `a=1&b=2` ，那么请求时不会携带`Content-Type`，如果网站有对`Content-Type`的判断的话，那么这次的请求很有可能报错。

:::

:::note 易错小结

请求库默认使用 utf8 编码，如果想要发送 gbk 编码的话，就需要使用 urlencode，然后设置对应的协议头。（相对还是比较麻烦的，暂时没找到比较有效的方法）

:::

### 重定向

requests 默认情况下是允许重定向请求的，而 httpx 则是默认不允许重定向，所以，如果项目中涉及到重定向的请求的话，是需要改点代码

如果要禁止重定向设置为 False，允许则为 True

requests 的参数是`allow_redirects`，而 httpx 则是`follow_redirects`，如果想要在 httpx 设置允许重定向的话，可以在 client 中设置，之后的请求都将进行重定向

```python
client.follow_redirects = True
```

不过在正常协议复现的情况下，是不建议允许重定向的，因为有可能重定向的那个请求有必要关键参数可能会在后续中使用到，而重定向就会直接跳过。

:::note 易错小结

requests 是 allow_redirects，httpx 是 follow_redirects

:::

### 拦截器(hook)

http 拦截器主要用途在请求时附带一些参数（比方说 post 请求对 body 进行加密，添加 authorization 协议头），在返回响应的时候作何处理（如请求重试，ip 异常更换 ip，对响应结果进行统一处理）

在 node 的请求库 axios 中的叫拦截器，而在 requests 中则是叫 hook，httpx 则是 event_hooks，下面对两者拦截器进行简单演示

requests

```python
import requests

def log_response(r, *args, **kwargs):
    request = r.request
    print(
        f"Response event hook: {request.method} {request.url} - Status {r.status_code}")


requests.get(url='http://example.com',
                 hooks=dict(response=[log_response]))
```

httpx

```python
import httpx

def log_request(request):
    print(
        f"Request event hook: {request.method} {request.url} - Waiting for response")


def log_response(response):
    request = response.request
    print(
        f"Response event hook: {request.method} {request.url} - Status {response.status_code}")


client = httpx.Client(
    event_hooks={'request': [log_request], 'response': [log_response]})

r = client.get(
    url='http://example.com')
```

requests 只支持响应后处理，还不支持请求发送前处理，而 httpx 则是都支持，所以更推荐使用 httpx。

## OCR

python 有一个 ocr 的识别库 [ddddocr](https://github.com/sml2h3/ddddocr)

主要是用于识别验证码，不过前提环境要求 python，通过`pip install ddddocr`进行安装，具体演示代码在官网文档上也有，这里就不做演示了。

还有一个搭建 api 服务的 [sml2h3/ocr_api_server: 使用 ddddocr 的最简 api 搭建项目，支持 docker (github.com)](https://github.com/sml2h3/ocr_api_server)

## 总结

主要是这个爬虫项目中所使用到了 OCR 识别验证码，加上太久没有编写 python 爬虫的项目，就打算编写一个 demo 例子，顺带巩固下 python 的一些语法特性。整体体验其实与 node 相差不大，但是 python 对异步的支持不如 js 的异步，并且 js 编写 json 数据更加灵活，最主要是 node 的三大特性**单线程、非阻塞 I/O、事件驱动**，如果不是特殊必要，我都会首选 node 的 axios 库来进行编写 http 请求。
