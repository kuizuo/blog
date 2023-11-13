---
layout: default
title:  Django项目中Cookie和Session应用
parent: 大江狗的Django入门教程
nav_order: 13
---

# Django项目中Cookie和Session应用场景及案例


## 目录


1. TOC
{:toc}

---
HTTP协议本身是”无状态”的，在一次请求和下一次请求之间没有任何状态保持，服务器无法识别来自同一用户的连续请求。有了cookie和session，服务器就可以利用它们记录客户端的访问状态了，这样用户就不用在每次访问不同页面都需要登录了。


## 什么是cookie，cookie的应用场景及缺点

cookie是一种数据存储技术, 它是将一段文本保存在客户端(浏览器或本地电脑)的一种技术，并且可以长时间的保存。当用户首次通过客户端访问服务器时，web服务器会发送给客户端的一小段信息。客户端浏览器会将这段信息以cookie形式保存在本地某个目录下的文件内。当客户端下次再发送请求时会自动将cookie也发送到服务器端，这样服务器端通过查验cookie内容就知道该客户端之前访问过了。

cookie的常见应用场景包括:
- 判断用户是否已经登录
- 记录用户登录信息(比如用户名，上次登录时间）
- 记录用户搜索关键词

cookie的缺点在于其并不可靠和不安全，主要原因如下:
- 浏览器不一定会保存服务器发来的cookie，用户可以通过设置选择是否禁用cookie。
- cookie是有生命周期的（通过Expire设置），如果超过周期，cookie就会被清除。
- HTTP数据通过明文发送，容易受到攻击，因此不能在cookie中存放敏感信息（比如信用卡号，密码等）。
- cookie以文件形式存储在客户端，用户可以随意修改的。

## Django中如何使用cookie

第一步：提供响应数据时设置cookie(保存到客户端)

```python
response.set_cookie(cookie_name, value, max_age = None, expires = None) 

# key : cookie的名称
# value : 保存的cookie的值
# max_age: 保存的时间，以秒为单位
# expires: 过期时间，为datetime对象或时间字符串
```

例子: `response.set_cookie('username','John',600)`

注意：Django的视图默认返回的response是不包含cookie的，需手动调用`set_cookie`方法。

下面是3个设置cookie的例子:

```python
# 例子1:不使用模板
response = HttpResponse("hello world")
response.set_cookie(key,value,max_age)
return response

# 例子2: 使用模板
response = render(request,'xxx.html', context)
response.set_cookie(key,value,max_age)
return response

# 例子3: 重定向
response = HttpResponseRedirect('/login/')
response.set_cookie(key,value,max_age)
return response
```

第二步： 获取COOKIES中的数据, 进行处理验证

```python
# 方法一
request.COOKIES['username']

# 方法二
request.COOKIES.get('username','')
```

客户端再次发送请求时，request会携带本地存储的cookie信息，视图中你可以通过`request.COOKIES`获取。

为了防止获取不能存在的Key报错，你可以通过如下方式检查一个cookie是否已存在。

```python
request.COOKIES.has_key('cookie_name')
```

如果你希望删除某个cookie，你可以使用如下方法：

```python
response.delete_cookie('username')
```

## Cookie使用示例

下面是django中使用cookie验证用户是否已登录的一个示例。用户首次登录时设置cookie，再次请求时验证请求携带的cookie。

```python
# 如果登录成功，设置cookie
def login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = User.objects.filter(username__exact=username, password__exact=password)

            if user:
                response = HttpResponseRedirect('/index/')
                # 将username写入浏览器cookie,有效时间为360秒
                response.set_cookie('username', username, 360)
                return response
            else:
                return HttpResponseRedirect('/login/')
                                                           
    else:
        form = LoginForm()

    return render(request, 'users/login.html', {'form': form})


# 通过cookie判断用户是否已登录
def index(request):
    # 读取客户端请求携带的cookie，如果不为空，表示为已登录帐号
    username = request.COOKIES.get('username', '')
    if not username:
        return HttpResponseRedirect('/login/')
    return render(request, 'index.html', {'username': username})
```

## 什么是session及session的工作原理

session又名会话，其功能与应用场景与cookie类似，用来存储少量的数据或信息。但由于数据存储在服务器上，而不是客户端上，所以比cookie更安全。不过当用户量非常大时，所有的会话信息都存储于服务器会对服务器造成一定的压力。

## Django中如何使用会话session
第一步：检查基本设置

Django中使用session首选需要确保`settings.py`中已开启了`SessionMiddleware`中间件。

```python
'django.contrib.sessions.middleware.SessionMiddleware',
```

Django默认使用数据库存储每个session的sessionid, 所以你还需确保`INSTALLED_APPS` 是包含如下app：

```python
'django.contrib.sessions',
```

当然你还可以使用更快的文件或缓存来存储会话信息，可以通过`SESSION_ENGINE`设置就行。

第二步：使用session

request.session是一个字典，你可以在视图和模板中直接使用它。

```python
# 设置session的值
request.session['key'] = value
request.session.set_expiry(time): 设置过期时间，0表示浏览器关闭则失效

# 获取session的值
request.session.get('key'，None)

# 删除session的值, 如果key不存在会报错
del request.session['key']

# 判断一个key是否在session里
'fav_color' in request.session

# 获取所有session的key和value
request.session.keys()
request.session.values()
request.session.items()
```

另外，`settings.py` 还有两项有关session比较重要的设置：
1、SESSION_COOKIE_AGE：以秒为单位，session的有效时间，可以通过`set_expiry `方法覆盖。
2、SESSION_EXPIRE_AT_BROWSER_CLOSE：默认为Flase，是否设置为浏览器关闭，会话自动失效。

## Session使用示例

下面是django中使用session进行用户登录和登出的一个示例。用户首次登录时设置session，退出登录时删除session。

```python
# 如果登录成功，设置session
def login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = User.objects.filter(username__exact=username, password__exact=password)
            if user:
                # 将username写入session，存入服务器
                request.session['username'] = username
                return HttpResponseRedirect('/index/')
            else:
                return HttpResponseRedirect('/login/')
    else:
        form = LoginForm()

    return render(request, 'users/login.html', {'form': form})


# 通过session判断用户是否已登录
def index(request):
    # 获取session中username
    username = request.session.get('username', '')
    if not username:
        return HttpResponseRedirect('/login/')
    return render(request, 'index.html', {'username': username})

# 退出登录
def logout(request):
    try:
        del request.session['username']
    except KeyError:
        pass
    return HttpResponse("You're logged out.")
```


下面是通过session控制不让用户连续评论两次的例子。实际应用中我们还可以通过session来控制用户登录时间，记录访问历史，记录购物车信息等等。

```python
from django.http import HttpResponse

def post_comment(request, new_comment):
    if request.session.get('has_commented', False):
        return HttpResponse("You've already commented.")
    c = comments.Comment(comment=new_comment)
    c.save()
    request.session['has_commented'] = True
    return HttpResponse('Thanks for your comment!')
```

## 小结

cookie和session都是一种存储少量数据的技术，用来记录客户端的访问状态，区别在于一个存储在客户端，一个存储在服务器端。Django中使用cookie和session都非常方便，都是基于先设置再获取的原则，可以灵活地用于各个场景。

原创不易，转载请注明来源。我是大江狗，一名Django技术开发爱好者。您可以通过搜索【<a href="https://blog.csdn.net/weixin_42134789">CSDN大江狗</a>】、【<a href="https://www.zhihu.com/people/shi-yun-bo-53">知乎大江狗</a>】和搜索微信公众号【Python Web与Django开发】关注我！

![Python Web与Django开发](../../assets/images/django.png)