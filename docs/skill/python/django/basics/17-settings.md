---
layout: default
title:  Django配置文件
parent: 大江狗的Django入门教程
nav_order: 17
---

# Django配置文件


## 目录


1. TOC
{:toc}

---
Django设置文件settings.py包含的选项非常多，但好消息是大部分不需要我们手动去设置。本章就来看下一些常用设置选项及它们背后的含义。


当我们使用`jango-admin.py startproject xxx`命令创建一个Django项目时，你会发现生成的`settings.py`已经包含了部分基本的默认设定，我们只需要修改和添加我们需要使用的设定就好了。一个项目完整的全局默认设置在`django/conf/global_settings.py`文件中。Django在编译时，会先载入global_settings.py中的全局默认配置值，然后加载用户指定的`settings.py`，重写部分全局默认设置。

## BASE_DIR 

默认值`BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))`。这个是Django项目文件夹所在目录得绝对路径，一般不要修改。 

## DEBUG

默认值是`True`。在本地开发测试环境下设置DEBUG=True可以显示bug信息，便于开发者找出代码错误所在。当你在部署项目在生产环境时，请切记设置DEBUG=False。这是因为生产环境下打开Debug一旦发生错误或异常会暴露很多敏感设置信息。

注意: 当你设置`DEBUG=False`, 你一定要设置`ALLOWED_HOSTS`选项, 否则会抛出异常。

## ALLOWED_HOSTS

默认值为空`[]`。设置ALLOWED_HOSTS是为了限定用户请求中的host值，以防止黑客构造包来进行头部攻击。该选项正确设置方式如下:

- DEBUG=True:  ALLOWED_HOSTS可以为空，也可设置为['127.0.0.01', 'localhost']

- DEBUG=False:  ALLOWED_HOSTS=['46.124.78.xx', 'www.bat.com'，'127.0.0.1']

当你关闭DEBUG时，HOST一般为服务器公网IP或者注册域名。 当你还需要使用子域名时，你可以用`.bat.com`。它将匹配`bat.com`, `www.bat.com`和`news.bat.com`。在正式部署项目时，请尽量不要设置`ALLOWED_HOSTS=['*']`。

## SECRET_KEY

SECRET_KEY是Django根据自己算法生成的一大串随机数，本质是个加密盐，用于防止CSRF（Cross-site request forgery）跨站请求伪造攻击。当部署Django项目到生产环境中时，Django文档建议不直接在`settings.py`里输入字符串，而是采取下面几种方法读取SECRET_KEY。

###  方法一: 从环境变量中读取SECRET_KEY
```python
import os
SECRET_KEY = os.environ['SECRET_KEY']
```

### 方法二: 从服务器上Django项目文件价外的某个文件读取
```python
with open('/etc/secret_key.txt') as f:
    SECRET_KEY = f.read().strip()
```


## INSTALLED_APPS

这个设置比较简单，也比较常用，用于增删一个项目(Project)所包含的应用(APP)。只有对列入此项的APP, Django才会生成相应的数据表。

```python

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'polls',  # 自定义的APP
]
```

## AUTH_USER_MODEL

默认为`auth.user`。也可以为自定义用户模型, 如`users.user`。


## STATIC_ROOT和STATIC_URL

这两个选项是关于静态文件(如CSS, JS,和图片)的最重要的设置，一般设置如下。STATIC_URL是静态文件URL，设置后可以通过使用`{% raw %}{% static 'assets/imges/xxx.jpg' %}{% endraw %}`方式直接访问/static/文件夹里的静态文件。如果你设置了STATIC_ROOT, 当你运行`python manage.py collectstatic`命令的时候，Django会将各app下所有名为static的文件夹及其子目录复制收集到STATIC_ROOT。把静态文件集中一起的目的是为了更方便地通过Apache或Nginx部署。

```python
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
```

一般情况下我们会尽量把静态文件只放在static文件夹或它的子目录下，所以上述两个设置对于一般项目是够的。那么问题来了，如果你还有一些文件夹中也有静态文件，可是文件夹并不是以static命名也不在static子目录里，此时你也希望搜集使用那些静态文件，你该怎么办呢？这时我们就要设置静态文件目录`STATICFILES_DIRS`值了。

## STATICFILES_DIRS

默认值为空。当你设置该选项后，`python manage.py collectstatic`命令会把static文件夹及静态文件目录`STATICFILES_DIRS`里的静态文件都复制到一份到`STATIC_ROOT`。比如下例中Django会将下面两个文件夹内容也复制到`STATIC_ROOT`。注意里面的路径必需是绝对路径哦。

```python
STATICFILES_DIRS = [
"/home/user/pictures",
"/opt/webfiles/myfiles",
]
```

## MEDIA_ROOT和MEDIA_URL

media文件价一般用于放置用户上传的文件。对于此文件夹的权限设置异常重要，因为用户可能会上传可执行的文件，影响网站和服务器的安全。对于此文件夹权限，建议使用`sudo chmod 755 media`命令设置成755，而不要使用777（可读、可写、可执行)。

```python
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
```

##  国际化(语言与时间)

```python
USE_TZ = True # 默认值True。
TIME_ZONE = 'Asia/Shanghai' # 设置时区
USE_I18N = True # 默认为True，是否启用自动翻译系统
USE_L10N = True # 默认False，以本地化格式显示数字和时间
```

## 邮箱服务配置

```python
EMAIL_HOST = 'smtp.qq.com' # 发送者邮箱服务器
EMAIL_PORT = 25 # 端口
EMAIL_HOST_USER = ''        # 发送者用户名（邮箱地址）
EMAIL_HOST_PASSWORD = ''    # 发送者密码
EMAIL_USE_SSL = True
DEFAULT_FROM_EMAIL = 'xxx@qq.com'
```

## 模板设置

如果你在根目录下建立了一个`templates`文件夹，专门用于存放属于项目的模板文件，你还需要在`settings.py`中显示地将模板目录设置为`BASE_DIR`目录下的`templates`文件夹。

```python
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')], # 设置项目模板目录
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
```

## 中间件设置

如果你希望在Django项目中使用自定义的中间件，你需要在 `MIDDLEWARE`选项里注册。注意：中间件的添加顺序很重要。

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'myapp.middleware.CustomMiddleware1', # 新增自定义中间件。
]
```

##  数据库设置

Django默认使用轻量级的SQLite数据库，无需进行任何设置开箱即用。如果你希望使用MySQL或则postgreSQL，你需要先在本地或服务器上安装MySQL或postgreSQL，创建数据库和用户并授权，然后再修改配置文件。

当然小编我并不建议在`settings.py`直接写入数据库密码，而是采取读取外部配置文件的方式，更安全。下面以MYSQL为例介绍了基本配置方式。

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',   # 数据库引擎
        'NAME': 'mydb',         # 你要存储数据的库名，事先要创建之
        'USER': 'xxs',         # 数据库用户名
        'PASSWORD': 'xxxx',     # 密码
        'HOST': 'localhost',    # 主机
        'PORT': '3306',         # 数据库使用的端口
    }
}
```

## 缓存设置
Django中提供了多种缓存方式，如果要使用缓存，需要先在`settings.py`中进行配置，然后应用。根据缓存介质的不同，你需要设置不同的缓存后台Backend。

比如如果你希望使用redis做缓存后台，你需要先安装`redis`和`django_redis`, 然后再修改`settings.py`中的缓存配置。

 ```python
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://your_host_ip:6379', # redis所在服务器或容器ip地址
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
             "PASSWORD": "your_pwd", # 你设置的密码
        },
    },
}
 ```

## Session相关设置

 ```python
SESSION_ENGINE = 'django.contrib.sessions.backends.db'  # 引擎（默认）
SESSION_COOKIE_NAME = "sessionid"  # Session的cookie保存在浏览器上时的key，
SESSION_COOKIE_PATH = "/"  # Session的cookie保存的路径（默认）
SESSION_COOKIE_DOMAIN = None  # Session的cookie保存的域名（默认）
SESSION_COOKIE_SECURE = False  # 是否Https传输cookie（默认）
SESSION_COOKIE_HTTPONLY = True  # 是否Session的cookie只支持http传输（默认）
SESSION_COOKIE_AGE = 60 * 30  # Session的cookie失效日期（30min）（默认）
SESSION_EXPIRE_AT_BROWSER_CLOSE = True  # 是否关闭浏览器使得Session过期（默认）
SESSION_SAVE_EVERY_REQUEST = True  # 是否每次请求都保存Session，默认修改之后才保存
 ```

## 小结

本文总结了Django项目 `settings.py`文件中常用设置选项及它们背后的含义，你都明白了吗?

原创不易，转载请注明来源。我是大江狗，一名Django技术开发爱好者。您可以通过搜索【<a href="https://blog.csdn.net/weixin_42134789">CSDN大江狗</a>】、【<a href="https://www.zhihu.com/people/shi-yun-bo-53">知乎大江狗</a>】和搜索微信公众号【Python Web与Django开发】关注我！

![Python Web与Django开发](../../assets/images/django.png)

