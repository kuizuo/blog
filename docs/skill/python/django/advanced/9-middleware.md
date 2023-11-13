---
layout: default
title:  Django中间件原理及示例
parent: 大江狗的Django进阶教程
nav_order: 9
---

# Django中间件原理及示例


## 目录


1. TOC
{:toc}

---
中间件(middleware)允许您在一个浏览器的请求在到达Django视图之前处理它，以及在视图返回的响应到达浏览器之前处理这个响应。本文着重分析Django中间件的工作原理和应用场景，介绍如何自定义中间件并提供一些示例。


## 什么是中间件及其应用场景

***中间件(middleware)是一个镶嵌到Django的request(请求)/response(响应)处理机制中的一个钩子(hooks) 框架。它是一个可以修改Django全局输入或输出的一个底层插件系统。***

上面这段话是Django官方文档中对于中间件的介绍，非常抽象难懂。小编我来尝试用浅显的语言再介绍一遍吧。我们首先要了解下Django的request/response处理机制，然后再看看中间件在整个处理机制中的角色及其工作原理。

HTTP Web服务器工作原理一般都是接收用户发来的请求(request), 然后给出响应(response)。Django也不例外，其一般工作方式是接收request请求和其它参数，交由视图(view)处理，然后给出它的响应(response): 渲染过的html文件或json格式的数据。然而在实际工作中Django并不是接收到request对象后，马上交给视图函数或类(view)处理，也不是在view执行后立马把response返回给用户。**一个请求在达到视图View处理前需要先经过一层一层的中间件处理，经过View处理后的响应也要经过一层一层的中间件处理才能返回给用户 **。

中间件(Middleware)在整个Django的request/response处理机制中的角色如下所示：

```bash
HttpRequest -> Middleware -> View -> Middleware -> HttpResponse
```

中间件常用于权限校验、限制用户请求、打印日志、改变输出内容等多种应用场景，比如：

- 禁止特定IP地址的用户或未登录的用户访问我们的View视图函数
- 对同一IP地址单位时间内发送的请求数量做出限制
- 在View视图函数执行前传递额外的变量或参数
- 在View视图函数执行前或执行后把特定信息打印到log日志
- 在View视图函数执行后对response数据进行修改后返回给用户

注意：装饰器也经常用于用户权限校验。但与装饰器不同，中间件对Django的输入或输出的改变是全局的。比如`@login_required`装饰器仅作用于单个视图函数。如果你希望实现全站只有登录用户才能访问，编写一个中间件是一个更好的解决方案。

## Django自带中间件

当你创建一个新Django项目时，你会发现`settings.py`里的`MIDDLEWARE`列表已经注册了一些Django自带的中间件，每个中间件都负责一个特定的功能。

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

每个中间件的功能如下,小编建议都保留:

- `SecurityMiddleware`：为request/response提供了几种安全改进;

- `SessionMiddleware`：开启session会话支持；

- `CommonMiddleware`：基于APPEND_SLASH和PREPEND_WWW的设置来重写URL，如果APPEND_SLASH设为True，并且初始URL 没有以斜线结尾以及在URLconf 中没找到对应定义，这时形成一个斜线结尾的新URL；

- `CsrfViewMiddleware`：添加跨站点请求伪造的保护，通过向POST表单添加一个隐藏的表单字段，并检查请求中是否有正确的值；

- `AuthenticationMiddleware`：在视图函数执行前向每个接收到的user对象添加HttpRequest属性，表示当前登录的用户，无它用不了`request.user`。

- `MessageMiddleware`：开启基于Cookie和会话的消息支持

- `XFrameOptionsMiddleware`：对点击劫持的保护

除此以外, Django还提供了压缩网站内容的`GZipMiddleware`，根据用户请求语言返回不同内容的`LocaleMiddleware`和给GET请求附加条件的`ConditionalGetMiddleware`。这些中间件都是可选的。

## Django的中间件执行顺序

当你在`settings.py`注册中间件时一定要要考虑中间件的执行顺序，中间件在request到达view之前是从上向下执行的，在view执行完后返回response过程中是从下向上执行的，如下图所示。举个例子，如果你自定义的中间件有依赖于`request.user`，那么你自定义的中间件一定要放在`AuthenticationMiddleware`的后面。

![image-20210322171209455](middleware.assets/image-20210322171209455.png)



## 自定义中间件

自定义中间件你首先要在app所属目录下新建一个文件`middleware.py`, 添加好编写的中间件代码，然后在项目`settings.py`中把它添加到`MIDDLEWARE`列表进行注册，添加时一定要注意顺序。

Django提供了两种编写自定义中间件的方式：函数和类，基本框架如下所示:

### 函数

```python
def simple_middleware(get_response):
    # 一次性设置和初始化
    def middleware(request):
        # 请求在到达视图前执行的代码
        response = get_response(request)
        # 响应在返回给客户端前执行的代码
        return response
    return middleware
```

当请求从浏览器发送到服务器视图时，将执行`response = get_response(request)`该行之前的所有代码。当响应从服务器返回到浏览器时，将执行`response = get_response(request)`此行之后的所有内容。

那么这条分界线`respone = get_response(request)`做什么的？**简而言之，它将调用列表中的下一个中间件。如果这是最后一个中间件，则将调用该视图。** 

***示例***

我们现在以函数编写一个名为`timeit_middleware`的中间件，打印出执行每个请求所花费的时间，代码如下所示：

```python
import time

def timeit_middleware(get_response):
    
    def middleware(request):
        start = time.time()
        response = get_response(request)
        end = time.time()
        print("请求花费时间: {}秒".format(end - start))
        return response

    return middleware
```

**注册中间件**

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'blog.middleware.timeit_middleware', # 新增
]
```

**执行效果**

每当Django处理一个请求时，终端(terminal)就会打印出请求花费时间，如下所示：

![image-20210322212937585](middleware.assets/image-20210322212937585.png)

### 使用类

 ```python
class SimpleMiddleware:
    def __init__(self, get_response):
        # 一次性设置和初始化
        self.get_response = get_response
        
    def __call__(self, request):
        # 视图函数执行前的代码
        response = self.get_response(request)
        # 视图函数执行后的代码
        return response
 ```

***示例***

我们现在以类来编写一个名为`LoginRequiredMiddleware`的中间件，实现全站要求登录，但是登录页面和开放白名单上的urls除外。代码如下所示：

```python
from django.shortcuts import redirect
from django.conf import settings

class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.login_url = settings.LOGIN_URL
        # 开放白名单，比如['/login/', '/admin/']
        self.open_urls = [self.login_url] + getattr(settings, 'OPEN_URLS', [])

    def __call__(self, request):        
        if not request.user.is_authenticated and request.path_info not in self.open_urls:
            return redirect(self.login_url + '?next=' + request.get_full_path())
        
        response = self.get_response(request) 
        return response
```

小知识: `request.path_info`用于获取当前请求的相对路径，如`/articles/`，而`request.get_full_path()`用于获取当前请求完整的相对路径，包括请求参数，如`/articles/?page=2`。使用`request.get_full_path()`时别忘了加括号哦，否则返回的是uwsgi请求对象，不是字符串。

**注册中间件**

修改`settings.py`, 注册中间件，并添加 `LOGIN_URL`和`OPEN_URLS`。

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'blog.middleware.timeit_middleware',
    'blog.middleware.LoginRequiredMiddleware',
]

LOGIN_URL = "/admin/login/"
OPEN_URLS = ["/admin/"]
```

**查看效果**

添加完中间件后，你访问任何非LOGIN_URL和OPEN_URLS里的urls，都需要你先进行登录，如下所示：

![image-20210322222204474](middleware.assets/image-20210322222204474.png)

## 其它中间件钩子函数

Django还提供了其它三个中间件钩子函数，分别在执行视图函数，处理异常和进行模板渲染时调用。

### process_view(request, view_func, view_args, view_kwargs)

该方法有四个参数

- request是HttpRequest对象。
- view_func是Django即将使用的视图函数。 （它是实际的函数对象，而不是函数的名称作为字符串。
- view_args是将传递给视图的位置参数的列表。
- view_kwargs是将传递给视图的关键字参数的字典。 view_args和view_kwargs都不包含第一个视图参数（request）。

Django会在调用视图函数之前调用process_view方法。它应该返回None或一个HttpResponse对象。 如果返回None，Django将继续处理这个请求，执行任何其他中间件的process_view方法，然后在执行相应的视图。 如果它返回一个HttpResponse对象，Django不会调用适当的视图函数。 它将执行中间件的process_response方法并将应用到该HttpResponse并返回结果。

### process_exception(self, request, exception)

该方法两个参数:

- 一个HttpRequest对象
- 一个exception是视图函数异常产生的Exception对象。

这个方法只有在视图函数中出现异常了才执行，它返回的值可以是一个None也可以是一个HttpResponse对象。如果是HttpResponse对象，Django将调用模板和中间件中的process_response方法，并返回给浏览器，否则将默认处理异常。如果返回一个None，则交给下一个中间件的process_exception方法来处理异常。该方法常用于发生异常时通知管理员或将其日志的形式记录下来。

### process_template_response(self, request, response)

该方法两个参数：

- 一个HttpRequest对象
- 一个response是TemplateResponse对象（由视图函数或者中间件产生）。

该方法是在视图函数执行完成后立即执行，但是它有一个前提条件，那就是视图函数返回的对象有一个render()方法（或者表明该对象是一个TemplateResponse对象)。该方法常用于向模板注入变量或则直接改变模板。

### 如何使用这3个钩子函数？

在函数或类的中间件中应该如何使用上面3个钩子函数呢? 具体实现方式如下：

**函数**

```python
from django.http import HttpResponse

def timeit_middleware(get_response):
    
    def middleware(request):
        response = get_response(request)
        return response
    
    def process_view(request, view_func, view_args, view_kwargs)
        return None or HttpResponse(xx)
 
    def process_exception(self, request, exception):
        return None or HttpResponse(xx)
    
    def process_template_response(self, request, response)
        return ...
    
    middleware.process_view = process_view
    middleware.process_exception = process_exception
    middleware.process_template_response = process_template_response
 
    return middleware
```



**类**

```python
class MyClassMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
 
    def __call__(self, request):
        return self.get_response(request)
    
    def process_view(request, view_func, view_args, view_kwargs)
        return None or HttpResponse(xx)
 
    def process_exception(self, request, exception):
        return None or HttpResponse(xx)
        # 例子: 打印出异常
        return HttpResponse(<h1>str(exception)</h1)
    
    # 该方法仅对TemplateResponse输入有用，对render方法失效
    def process_template_response(self, request, response)
        response.context_data['title'] = 'New title'
        return response
```

## 小结

本文介绍了Django中间件(Middleware)的工作原理，执行顺序及如何自定义中间件。了解中间件一定要先对Django的request/response处理过程非常了解。当你希望在视图函数执行请求前或执行请求后添加额外的功能，且这种功能是全局性的（针对所有的request或view或response), 那么使用中间件是最好的实现方式。

原创不易，转载请注明来源。我是大江狗，一名Django技术开发爱好者。您可以通过搜索【<a href="https://blog.csdn.net/weixin_42134789">CSDN大江狗</a>】、【<a href="https://www.zhihu.com/people/shi-yun-bo-53">知乎大江狗</a>】和搜索微信公众号【Python Web与Django开发】关注我！

![Python Web与Django开发](../../assets/images/django.png)


