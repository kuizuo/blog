---
slug: brief-talk-http
title: 浅谈HTTP
date: 2020-09-29
authors: kuizuo
tags: [http]
keywords: [http]
description: 记录 git 操作失误导致代码丢失与找回的过程
---

<!-- truncate -->

关于 HTTP 我不讲理论，只讲一下具体的用途。

## GET 请求之发送验证码

首先我举一个例子，收过短信验证码吧，一般来说在你注册账号的时候就会用到，会有一个点击发送验证码的按钮，这里以 网址 [114 预约挂号](https://www.114yygh.com/) 为例

![image-20200928234944932](https://img.kuizuo.cn/image-20200928234944932.png)

输入完手机号，点击获取验证码就能收到验证码，但这背后的原理又是啥，服务器那边怎么知道我要验证码，并且我输入正确的验证码就进入，错误的就不行。而这正是网络协议 HTTP（关于 HTTP 相关的这里不做过多讲述，希望读者能自行百度了解），我先说下点击了获取验证码发生了什么，通过抓包工具可以获取到如下请求

```http
GET https://www.114yygh.com/web/common/verify-code/get?_time=1601308153790&mobile=15212345678&smsKey=LOGIN HTTP/1.1
Host: www.114yygh.com
Connection: keep-alive
Accept: application/json, text/plain, */*
Request-Source: PC
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1.70.3775.400 QQBrowser/10.6.4208.400
Content-Type: application/json;charset=UTF-8
Referer: https://www.114yygh.com/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
```

首先我们向服务器发送了一个如上的请求，这是一个 GET 请求，同时请求的链接（url）为`https://www.114yygh.com/web/common/verify-code/get?_time=1601308153790&mobile=15212345678&smsKey=LOGIN`

如果你会点英文的话，可能会理解其中的含义，主要就这几个参数`verify-code`验证码，`_time=1601308153790`时间戳（时间戳是一个记录时间的东西，用当前时间减去`1970-01-01 08:00:00`即可得到，你可以通过这个工具[时间戳在线转化](https://tool.lu/timestamp/)，这里的`1601308153790`所对应的时间为`2020-09-28 23:58:06`）还有一个`mobile=15212345678`，这个`15212345678`是我刚刚输入的手机号。这是向服务器请求的数据，那在来看看服务器返回给我们的是什么

```http
HTTP/1.1 200
Date: Mon, 28 Sep 2020 15:49:15 GMT
Content-Type: application/json;charset=UTF-8
Content-Length: 57
Connection: keep-alive
Set-Cookie: hyde_session=Kd10cra3X4yNBePaaQTKUkuYgX9J6Hfx_5337693
Set-Cookie: hyde_session_tm=1601308154470; Domain=.114yygh.com; Path=/; HttpOnly
Content-Security-Policy: : default-src *.114yygh.com *.qq.com *.baidu.com; font-src * data:
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
X-Via-JSL: d8c5e31,-
X-Cache: bypass

{"resCode":0,"msg":null,"data":{"endMilliseconds":59997}}
```

只需要关注最后一行即可，其中 resCode 为 0，同时手机号`15212345678`也收到了验证码，貌似 resCode 为 0 就决定了服务器是否有给手机号发送短信，事实上也是的，那么说了这么多，有什么用呢，用处可大了。

既然这样，我知道了发送上面的那个请求服务器就能给对应的手机号发送验证码，那么我能不能将上面那个请求的手机号给改一下，改成`15287654321`，事实上是完全没问题的，这里我就放一张 HTTP 测试工具的截图。

![image-20200929001306474](https://img.kuizuo.cn/image-20200929001306474.png)

那么是不是我多请求这样像服务器请求，我就能源源不断的收到验证码，现实很美好，人家服务器也不傻，我再一次向服务器发送请求，服务器给我的结果是

```
{"resCode":10000,"msg":"请58秒后重试","data":null}
```

没错，就需要等，而且这里的 resCode 也不为 0，那么既然要等一分钟的话，我能不能写个定时脚本，每隔一分钟发送一次，人家服务器也不傻，一般来说，一个手机号最多也就收 5 次验证码，多了就会提示明天再重试，或者今天收到的验证码过多等等。而外面的炸则是通过收集几百个这样的请求，然后将手机号替换成要轰炸的，即可实现多平台验证码轰炸一个手机号。

现在你可能已经知道了初步了解 HTTP 请求，但一般的网站都不会像这个这么简单的，明文标码，通常都会进行效验，例如图片验证码，滑块，点字，点图等等，并且还会进行加密操作处理，而这才算真正的难点。

## POST 请求之登录

既然发验证码是这样，那如果是登录呢，下面就用网站 [万创帮](https://m.wcbchina.com/) 为例，首先进入登录界面

![image-20200929003119277](https://img.kuizuo.cn/image-20200929003119277.png)

输入手机号和密码，点击登录，同样的我们可以通过抓包工具获取到对应的 HTTP 请求，如下

```http
POST https://m.wcbchina.com/api/login/login?rnd=0.6463111465399551 HTTP/1.1
Host: m.wcbchina.com
Connection: keep-alive
Content-Length: 149
Pragma: no-cache
Cache-Control: no-cache
Accept: application/json, text/javascript, */*; q=0.01
Origin: https://m.wcbchina.com
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Linux; Android 8.0.0; Pixel 2 XL Build/OPD1.170816.004) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Mobile Safari/537.36
Content-Type: application/json
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9

{"auth":{"timestamp":1601312429287,"sign":"777473FB2A1838DBD64BA7A11C98911B"},"username":"15212345678","password":"E9BC0E13A8A16CBB07B175D92A113126"}
```

貌似比上面那个发验证码的复杂，确实，这是一个 POST 请求，你在链接上看不出什么有效信息，在最后一行才是关键。这里的`timestamp`也就是时间戳，记录时间的，username 是我们输入的手机号（账号）没什么问题，这里的 sign 和 password 的内容又是啥？这就是加密，让你不能简单单纯的通过替换文本来实现登录，这就来分析一下他到底怎么加密的。

通过在浏览器按下 F12 键，打开控制台面板，接着点击 Network，这里会将我们发送的请求记录下来

![image-20200929004247182](https://img.kuizuo.cn/image-20200929004247182.png)

同时鼠标停在 Initiator 上有如下结果

![image-20200929004449660](https://img.kuizuo.cn/image-20200929004449660.png)

不管三七二十一，点击跳转到对应的代码先，然后在左边下一个断点

![image-20200929004628978](https://img.kuizuo.cn/image-20200929004628978.png)

这时候我们在点击登录按钮看看

![image-20200929004713733](https://img.kuizuo.cn/image-20200929004713733.png)

没错，浏览器这时候停了下来，停在了我下断点的地方，通过函数名也可以猜到这个是发送的，对应的肯定在上面，通过右边的 Call Stack 函数调用栈即可追随上一函数

![image-20200929004943674](https://img.kuizuo.cn/image-20200929004943674.png)

在这里我看到了原文的信息，这是通过 Jquery 通过 id 获取元素的值，也就是这里的手机号和密码，在这里还都是原文，点到下一个函数则变成了密文，那么肯定是上一个函数做了手脚。

认真观察，N 这个是我们的密码，但对 N 进行了一个操作也就是 `a.hex_md5(N)`，没错，这就是 md5 加密。有关加密的可以看看我写过的 [浅谈加密算法](./docs/brief-talk-encryption-algorithm)

那么通过加密工具将 md5 加密是否能得到我们要的加密结果，如下

![image-20200929005711500](https://img.kuizuo.cn/image-20200929005711500.png)

`E9BC0E13A8A16CBB07B175D92A113126`在看看 Password 的值，一模一样，看来已经解决了一个参数，那么还有一个`sign`呢。貌似右边的函数调用栈都不好使，我试试搜索字符串 sign 看看

![image-20200929005911119](https://img.kuizuo.cn/image-20200929005911119.png)

好家伙，直接定位到了，那么同样的在这里下一个断点，查看一下到底发生了什么（实际上 js 静态分析就完事了，这个网站太简单了）

这里的 N 看来就决定了 sign，而 N 也是通过 md5 加密的，不过原文我还不知道，让代码执行到这一行看看结果

![image-20200929010417525](https://img.kuizuo.cn/image-20200929010417525.png)

这里的 c 就是时间戳，而 token 和 password 都是未定义，那么就好办了。这里明文也就是 c `1601312429287`，那么用加密工具即可得到`777473FB2A1838DBD64BA7A11C98911B`，那么参数都搞定好了， 只需要替换一下账号，然后将正确的密码通过加密算法（这里为 md5）生成，同时对 sign 也生成出来，然后提交给服务器就能收到我们登录的请求，就认定为我们登录了，记录为在线用户。

如果我用的加密算法错了，或者我分析错了，提交给服务器会是怎么样的

![image-20200929011055451](https://img.kuizuo.cn/image-20200929011055451.png)

例如我这里的 sign 算法是错了（将结尾的 B 改成了 A），发送给服务器，服务器返回给我们则是失败的结果，原因很简单，就是为了防止别人恶意登录所添加的效验，提交的数据伪成败，就决定了服务器给我们结果是成败。

## 总结

通过上面的一些例子，只要能伪造请求，发送给服务器，就能获取我们想要的结果或者目的，事实上也是如此，但伪造数据的难易则要由所对应的网站而定，有的网站压根就没没什么难度，而有的你搞一天都未必能搞的出来。如今的网站在这方面也都下足了功夫，想要轻松的伪造请求可不是件容易的事情了。

也正是因为我学了 HTTP 请求与 JS 逆向分析，我能做的也就更多，而正是基于 HTTP 协议下，其中一个就是有关于超星刷课软件的例子，如果我没有学过这些，我就不可能写出来。

后续会有关 HTTP 请求这方面都会放在逆向这个分类下，比如一些网站的加密算法和常见的坑等等。
