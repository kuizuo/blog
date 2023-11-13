---
layout: default
title: Django性能优化大全
parent: 大江狗的Django进阶教程
nav_order: 17
---

# Django性能优化大全


## 目录


1. TOC
{:toc}

---
慢是相对的。同样是人，有的人跑得快，有的人跑得慢。如果你的Python程序或Django项目运行速度慢，先别急着怪Django。其实程序运行效率是可以通过提升硬件水平、架构和数据库优化和改进算法来大大提升的。本文将列举一些主要Django性能优化手段，完全可以让你的Django程序跑得飞快。

过度性能优化是没有必要甚至有害的，因为花大力气带来的毫秒级的响应提升你的用户可能根本感知不到，毕竟开发人员的时间也很宝贵。

## 性能优化指标

在对一个Web项目进行性能优化时，我们通常需要考虑如下几个指标：

- 响应时间
- 最大并发连接数
- 代码的行数
- 函数调用次数
- 内存占用情况
- CPU占比

其中响应时间（服务器从接收用户请求，处理该请求并返回结果所需的总的时间）通常是最重要的指标，因为过长的响应时间会让用户厌倦等待，转投其它网站或APP。当你的用户数量变得非常庞大，如何提高最大并发连接数，减少内存消耗也将变得非常重要。

在开发环境中，我们一般建议使用`django-debug-toolbar`和`django-silk`来进行性能监测分析。它们提供了每次用户请求的响应时间，并告诉你程序执行过程哪个环节(比如SQL查询)最消耗时间。

对于中大型网站或Web APP而言，最影响网站性能的就是数据库查询部分了。一是反复从数据库读写数据很消耗时间和计算资源，二是当返回的查询数据集queryset非常大时还会占据很多内存。我们先从这部分优化做起。

## 数据库查询优化
### 利用Queryset的惰性和缓存，避免重复查询

充分利用Django的QuerySet的惰性和自带缓存特性，可以帮助我们减少数据库查询次数。比如下例中例1比例2要好。因为在你打印文章标题后，Django不仅执行了数据库查询，还把查询到的`article_list`放在了缓存里，下次可以在其它地方复用，而例2就不行了。

```python
# 例1: 利用了缓存特性 - Good
article_list = Article.objects.filter(title__contains="django")
for article in article_list:
    print(article.title)

# 例2: Bad
for article in Article.objects.filter(title__contains="django"):
    print(article.title)
```

但有时我们只希望了解查询的结果是否存在或查询结果的数量，这时可以使用`exists()`和`count()`方法，如下所示。这样就不会浪费资源查询一个用不到的数据集，还可以节省内存。

```python
# 例3: Good
article_list = Article.objects.filter(title__contains="django")
if article_list.exists():
    print("Records found.")
else:
    print("No records")
    
# 例4: Good
count = Article.objects.filter(title__contains="django").count()
```

### 一次查询所有需要的关联模型数据
假设我们有一个文章(Article)模型，其与类别(Category)是单对多的关系(ForeignKey), 与标签(Tag)是多对多的关系(ManyToMany)。我们需要编写一个`article_list`的函数视图，以列表形式显示文章清单及每篇文章的类别和标签，你的模板文件可能如下所示：


```bash
{% raw %}<ul>
{% for article in articles %}
    <li>{{ article.title }} </li>
    <li>{{ article.category.name }}</li>
    <li>
        {% for tag in article.tags.all %}
           {{ tag.name }},
        {% endfor %}
    </li>
{% endfor %}
</ul>{% endraw %}
```

在模板里每进行一次for循环获取关联对象category和tag的信息，Django就要单独进行一次数据库查询，造成了极大资源浪费。我们完全可以使用`select_related`方法和`prefetch_related`方法一次性从数据库获取单对多和多对多关联模型数据，这样在模板中遍历时Django也不会执行数据库查询了。

```python
# 仅获取文章数据 - Bad
def article_list(request):
    articles = Article.objects.all()
    return render(request, 'blog/article_list.html',{'articles': articles, })

# 一次性提取关联模型数据 - Good
def article_list(request):
    articles = Article.objects.all().select_related('category').prefecth_related('tags')
    return render(request, 'blog/article_list.html', {'articles': articles, })
```

### 仅查询需要用到的数据

默认情况下Django会从数据库中提取所有字段，但是当数据表有很多列很多行的时候，告诉Django提取哪些特定的字段就非常有意义了。假如我们数据库中有100万篇文章，需要循环打印每篇文章的标题。如果按例4操作，我们会将每篇文章对象的全部信息都提取出来载入到内存中，不仅花费更多时间查询，还会大量占用内存，而最后只用了title这一个字段，这是完全没有必要的。我们完全可以使用`values`和`value_list`方法按需提取数据，比如只获取文章的id和title，节省查询时间和内存(例6-例8)。

```python
# 例子5: Bad
article_list = Article.objects.all()
if article_list:
    print(article.title)

# 例子6: Good - 字典格式数据
article_list = Article.objects.values('id', 'title')
if article_list:
    print(article.title)

# 例子7: Good - 元组格式数据
article_list = Article.objects.values_list('id', 'title')
if article_list:
    print(article.title)
    
# 例子8: Good - 列表格式数据
article_list = Article.objects.values_list('id', 'title', flat=True)
if article_list:
    print(article.title)
```

除此以外，Django项目还可以使用`defer`和`only`这两个查询方法来实现这一点。第一个用于指定哪些字段不要加载，第二个用于指定只加载哪些字段。

### 使用分页，限制最大页数

事实前面代码可以进一步优化，比如使用分页仅展示用户所需要的数据，而不是一下子查询所有数据。同时使用分页时也最好控制最大页数。比如当你的数据库有100万篇文章时，每页即使展示100篇，也需要1万页展示给你的用户，这是完全没有必要的。你可以完全只展示前200页的数据，如下所示：

```python
LIMIT = 100 * 200

data = Articles.objects.all()[:(LIMIT + 1)]
if len(data) > LIMIT:
    raise ExceededLimit(LIMIT)

return data
```

### 数据库设置优化

如果你使用单个数据库，你可以采用如下手段进行优化：

- 建立模型时能用`CharField`确定长度的字段尽量不用不用`TextField`, 可节省存储空间；
- 可以给搜索频率高的字段属性，在定义模型时使用索引(`db_index=True`)；
- 持久化数据库连接。

没有持久化连接，Django每个请求都会与数据库创建一个连接，直到请求结束，关闭连接。如果数据库不在本地，每次建立和关闭连接也需要花费一些时间。设置持久化连接时间，仅需要添加`CONN_MAX_AGE`参数到你的数据库设置中，如下所示：

```python
DATABASES = {
    ‘default’: {
        ‘ENGINE’: ‘django.db.backends.postgresql_psycopg2’,
        ‘NAME’: ‘postgres’,
        ‘CONN_MAX_AGE’: 60, # 60秒
    }
}
```

当然CONN_MAX_AGE也不宜设置过大，因为每个数据库并发连接数有上限的(比如mysql默认的最大并发连接数是100个)。如果CONN_MAX_AGE设置过大，会导致mysql 数据库连接数飙升很快达到上限。当并发请求数量很高时，CONN_MAX_AGE应该设低点，比如30s, 10s或5s。当并发请求数不高时，这个值可以设得长一点，比如60s或5分钟。

当你的用户非常多、数据量非常大时，你可以考虑读写分离、主从复制、分表分库的多数据库服务器架构。这种架构上的布局是对所有web开发语言适用的，并不仅仅局限于Django，这里不做进一步展开了。

## 缓存
缓存是一类可以更快的读取数据的介质统称，也指其它可以加快数据读取的存储方式。一般用来存储临时数据，常用介质的是读取速度很快的内存。一般来说从数据库多次把所需要的数据提取出来，要比从内存或者硬盘等一次读出来付出的成本大很多。对于中大型网站而言，使用缓存减少对数据库的访问次数是提升网站性能的关键之一。

### 视图缓存

```python
from django.views.decorators.cache import cache_page

@cache_page(60 * 15)
def my_view(request):
    ...
```

### 使用@cached_property装饰器缓存计算属性

对于不经常变动的计算属性，可以使用`@cached_property`装饰器缓存结果。

### 缓存临时性数据比如sessions

Django的sessions默认是存在数据库中的，这样的话每一个请求Django都要使用sql查询会话数据，然后获得用户对象的信息。对于临时性的数据比如sessions和messages，最好将它们放到缓存里，也可以减少SQL查询次数。

```python
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
```

### 模版缓存

默认情况下Django每处理一个请求都会使用模版加载器都会去文件系统搜索模板，然后渲染这些模版。你可以通过使用`cached.Loader`开启模板缓存加载。这时Django只会查找并且解析你的模版一次，可以大大提升模板渲染效率。

```python
TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [BASE_DIR / 'templates'],
    'OPTIONS': {
        'loaders': [
            ('django.template.loaders.cached.Loader', [
                'django.template.loaders.filesystem.Loader',
                'django.template.loaders.app_directories.Loader',
                'path.to.custom.Loader',
            ]),
        ],
    },
}]
```

注意：不建议在开发环境中(Debug=True)时开启缓存加载，因为修改模板后你不能及时看到修改后的效果。

另外模板文件中建议使用with标签缓存视图传来的数据，便于下一次时使用。对于公用的html片段，也建议使用缓存。

```python
{% raw %}{% load cache %}
{% cache 500 sidebar request.user.username %}
    .. sidebar for logged in user ..
{% endcache %}{% endraw %}
```

## 静态文件
压缩 HTML、CSS 和 JavaScript等静态文件可以节省带宽和传输时间。Django 自带的压缩工具有`GzipMiddleware` 中间件和 `spaceless` 模板 Tag。使用Python压缩静态文件会影响性能，一个更好的方法是通过 Apache、Nginx 等服务器来对输出内容进行压缩。例如Nginx服务器支持`gzip`压缩，同时可以通过`expires`选项设置静态文件的缓存时间。

更多关于Nginx的配置见：

- https://pythondjango.cn/python/tools/5-nginx-configuration/

原创不易，转载请注明来源。我是大江狗，一名Django技术开发爱好者。您可以通过搜索【<a href="https://blog.csdn.net/weixin_42134789">CSDN大江狗</a>】、【<a href="https://www.zhihu.com/people/shi-yun-bo-53">知乎大江狗</a>】和搜索微信公众号【Python Web与Django开发】关注我！

![Python Web与Django开发](../../assets/images/django.png)