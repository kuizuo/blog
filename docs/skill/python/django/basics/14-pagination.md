---
layout: default
title:  Django分页及通用模板
parent: 大江狗的Django入门教程
nav_order: 14
---

# Django项目中如何使用分页及通用模板


## 目录


1. TOC
{:toc}

---
Django作为Python Web开发框架的一哥，提供了企业级网站开发所需要的几乎所有功能，其中就包括自带分页功能。利用Django自带的Paginator类，我们可以很轻松地实现分页。本章将介绍如何在函数视图和基于类的视图中使用分页，并提供两个用于展示分页链接的通用模板。


## 为什么要分页?

当你的数据库数据量非常大时，如果一次将这些数据查询出来, 必然加大了服务器内存的负载,降低系统的运行速度。一种更好的方式是将数据分段展示给用户，这就是分页(pagination)的作用。

## 函数视图中使用分页
以博客为例，在Django视图函数中使用Paginator类对首页文章列表进行分页。它会向模板传递2个重要参数：

1. `page_obj`: 分页后的对象列表，在模板中使用for循环遍历即可；
2. `is_paginated`: 可选参数。当总页数不超过1页，值为False，此时模板不显示任何分页链接 。

 ```python
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import Article
from django.shortcuts import render

def article_list(request):
    queryset = Article.objects.filter(status='p').order_by('-pub_date')
    paginator = Paginator(queryset, 10)  # 实例化一个分页对象, 每页显示10个
    page = request.GET.get('page')  # 从URL通过get页码，如?page=3
    try:
        page_obj = paginator.page(page)
    except PageNotAnInteger:
        page_obj = paginator.page(1) # 如果传入page参数不是整数，默认第一页
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)
    is_paginated = True if paginator.num_pages > 1 else False # 如果页数小于1不使用分页
    context = {'page_obj': page_obj, 'is_paginated': is_paginated}
    return render(request, 'blog/article_list.html', context)
 ```

## 基于类的视图中使用分页

在基于类的视图`ListView`中使用分页，只需设置`paginate_by`这个参数即可。它同样会向模板传递`page_obj`和`is_paginated`这2个参数。

```
from django.views.generic import ListView
from .models import Article

class ArticleListView(ListView):
    queryset = Article.objects.filter(status='p').order_by('-pub_date')
    template_name = "blog/article_list.html"
    paginate_by = 10 # 每页10条
```

## 展示分页链接的通用模板

这里提供了两种展示分页链接的通用模板，对基于函数的视图和类视图都是适用的。当`is_paginated=True`时展示分页链接。

方式1： 上一页, Page 1 of 3, 下一页

```html
{% raw %}
 <ul> 
{% for article in page_obj %} 
   <li>{{ article.title }}</li> 
{% endfor %}
</ul>

{% if is_paginated %}
<div class="pagination">
    <span class="step-links">
        {% if page_obj.has_previous %}
            <a href="?page=1">&laquo; first</a>
            <a href="?page={{ page_obj.previous_page_number }}">上一页</a>
        {% endif %}

        <span class="current">
            Page {{ page_obj.number }} of {{ page_obj.paginator.num_pages }}.
        </span>

        {% if page_obj.has_next %}
            <a href="?page={{ page_obj.next_page_number }}">下一页</a>
            <a href="?page={{ page_obj.paginator.num_pages }}">last &raquo;</a>
        {% endif %}
    </span>
</div>
{% endif %}{% endraw %}
```

方式2： 上一页, 1, 2, 3, 4, 5, 6, 7, 8, ... 下一页。本例加入了Bootstrap 4的样式美化（推荐)。

```html
{% raw %}
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
 
{% if page_obj %}
    <ul> 
    {% for article in page_obj %}
       <li> {{ article.title }</li>
     {% endfor %}
   </ul>

   {# 分页链接 #}
   {% if is_paginated %}
     <ul class="pagination">
    {% if page_obj.has_previous %}
      <li class="page-item"><a class="page-link" href="?page={{ page_obj.previous_page_number }}">Previous</a></li>
    {% else %}
      <li class="page-item disabled"><span class="page-link">Previous</span></li>
    {% endif %}
 
    {% for i in page_obj.paginator.page_range %}
        {% if page_obj.number == i %}
      <li class="page-item active"><span class="page-link"> {{ i }} <span class="sr-only">(current)</span></span></li>
       {% else %}
        <li class="page-item"><a class="page-link" href="?page={{ i }}">{{ i }}</a></li>
       {% endif %}
    {% endfor %}
 
      {% if page_obj.has_next %}
      <li class="page-item"><a class="page-link" href="?page={{ page_obj.next_page_number }}">Next</a></li>
    {% else %}
      <li class="page-item disabled"><span class="page-link">Next</span></li>
    {% endif %}
    </ul>
    {% endif %}
 
{% else %}
{# 注释: 这里可以写自己的句子 #}
{% endif %}{% endraw %}
```

## 小结

本文总结了为什么要使用分页，以及如何在Django函数视图和基于类的视图中使用分页，并提供了两个用于展示分页链接的通用模板。

原创不易，转载请注明来源。我是大江狗，一名Django技术开发爱好者。您可以通过搜索【<a href="https://blog.csdn.net/weixin_42134789">CSDN大江狗</a>】、【<a href="https://www.zhihu.com/people/shi-yun-bo-53">知乎大江狗</a>】和搜索微信公众号【Python Web与Django开发】关注我！

![Python Web与Django开发](../../assets/images/django.png)

