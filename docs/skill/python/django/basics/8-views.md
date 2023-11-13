---
layout: default
title: Django视图及通用类视图
parent: 大江狗的Django入门教程
nav_order: 8
---

# Django函数视图及通用类视图


## 目录


1. TOC
{:toc}

---
Django的视图(view)是处理业务逻辑的核心，它负责处理用户的请求并返回响应数据。Django提供了两种编写视图的方式：基于函数的视图和基于类的视图。本章会详细介绍如何编写视图以及如何使用Django提供的通用类视图。


## 什么是视图(View)及其工作原理
Django的Web开发也遵循经典软件设计MVC模式开发的。View (视图) 主要根据用户的请求返回数据，用来展示用户可以看到的内容(比如网页，图片)，也可以用来处理用户提交的数据，比如保存到数据库中。Django的视图(`views.py`）通常和URL路由(URLconf)一起工作的。服务器在收到用户通过浏览器发来的请求后，会根据用户请求的url地址和`urls.py`里配置的url-视图映射关系，去执行相应视图函数或视图类，从而返回给客户端响应数据。

我们先看一个最简单的函数视图。当用户发来一个请求`request`时，我们通过`HttpResponse`打印出`Hello， World!`。

```html
# views.py
from django.http import HttpResponse

def index(request):
    return HttpResponse("Hello， World!")
```

**提示**：每个视图函数的第一个默认参数都必需是`request`, 它是一个全局变量。Django把每个用户请求封装成了`request`对象，它包含里当前请求的所有信息，比如请求路径`request.path`, 当前用户`request.user`以及用户通过POST提交的数据`request.POST`。

上面例子过于简单。在实际Web开发过程中，我们的View不仅要负责从数据库读写数据，还需要指定显示内容的模板，并提供模板渲染页面所需的内容对象(`context object`)。接下来我们要看一个更接近现实的案例。

## 接近现实的函数视图

我们依然以`blog`为例，需要编写两个视图函数，一个用于展示文章列表，一个用于展示文章详情，你的`urls.py`和`views.py`正常情况下应如下所示：

```python
# blog/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('blog/', views.index, name='index'),
    path('blog/articles/<int:id>/', views.article_detail, name='article_detail'),
]

# blog/views.py
from django.shortcuts import render, get_object_or_404
from .models import Article

# 展示所有文章
def index(request):
    latest_articles = Article.objects.all().order_by('-pub_date')
    return render(request, 'blog/article_list.html', {"latest_articles": latest_articles})

# 展示所有文章
def article_detail(request, id):
    article = get_object_or_404(Article, pk=id)
    return render(request, 'blog/article_detail.html', {"article": article})
```
那么上面这段代码是如何工作的呢？

- 当用户在浏览器输入`/blog/`时，URL收到请求后会调用视图`views.py`里的`index`函数，展示所有文章。
- 当用户在浏览器输入`/blog/article/5/`时，URL不仅调用了`views.py`里的`article_detail`函数，而且还把参数文章id通过`<int:id>`括号的形式传递给了视图里的`article_detail`函数。。
- views.py里的index函数先提取要展示的数据对象列表`latest_articles`, 然后通过`render`方法传递给模板`blog/article_list.html`.。
- views.py里的`article_detail`方法先通过`get_object_or_404`方法和id调取某篇具体的文章对象article，然后通过render方法传递给模板`blog/article_detail.html`显示。

在本例中，我们使用了视图函数里常用的2个便捷方法`render()`和`get_object_or_404()`。

- `render`方法有4个参数。第一个是`request`, 第二个是模板的名称和位置，第三个是需要传递给模板的内容, 也被称为`context object`。第四个参数是可选参数`content_type`（内容类型), 我们什么也没写。
- `get_object_or_404`方法第一个参数是模型Models或数据集queryset的名字，第二个参数是需要满足的条件（比如pk = id, title = 'python')。当需要获取的对象不存在时，给方法会自动返回Http 404错误。

下图是模板的代码。模板可以直接调用通过视图传递过来的内容。

```html
# blog/article_list.html
{% raw %} 
{% block content %}
{% for article in latest_articles %}
     {{ article.title }}
     {{ article.pub_date }}
{% endfor %}
{% endblock %}

# blog/article_detail.html
{% block content %}
   {{ article.title }}
   {{ article.pub_date }}
   {{ article.body }}
{% endblock %}{% endraw %}
```

## 更复杂的案例: 视图处理用户提交的数据

视图View不仅用于确定给客户展示什么内容，以什么形式展示，而且也用来处理用户通过表单提交的数据。我们再来看两个创建和修改文章的视图函数`article_create`和`article_update`，看看它们是如何处理用户通过表单POST提交过来的数据。

```python
 from django.shortcuts import render, redirect, get_object_or_404
 from django.urls import reverse
 from .models import Article
 from .forms import ArticleForm
 
 # 创建文章
 def article_create(request):
     # 如果用户通过POST提交，通过request.POST获取提交数据
     if request.method == "POST":
         # 将用户提交数据与ArticleForm表单绑定
         form = ArticleForm(request.POST)
         # 表单验证，如果表单有效，将数据存入数据库
         if form.is_valid():
             form.save()
             # 创建成功，跳转到文章列表
             return redirect(reverse("blog:article_list"))
     else:
         # 否则空表单
         form = ArticleForm()
     return render(request, "blog/article_form.html", { "form": form, })

 # 更新文章
 def article_update(request, pk):
     # 从url里获取单篇文章的id值，然后查询数据库获得单个对象实例
     article = get_object_or_404(Article, pk=id)
     
     # 如果用户通过POST提交，通过request.POST获取提交数据
     if request.method == 'POST':
         # 将用户提交数据与ArticleForm表单绑定，进行验证
         form = ArticleForm(instance=article, data=request.POST)
         if form.is_valid():
             form.save()
             # 更新成功，跳转到文章详情
             return redirect(reverse("blog:article_detail", args=[pk,]))
     else:
         # 否则用实例生成表单
         form = ArticleForm(instance=article)

     return render(request, "blog/article_form.html", { "form": form, "object": article})
```

我们给每一行代码添加了说明。值得一提的是在创建和更新文章时我们向模板传递了`form`这个变量，模板会根据我们自定义的Form类自动生成表单。我们还使用了自定义的Form类对用户提交的数据(`request.POST`)进行验证,并将通过验证的数据存入数据库。

这里所使用`ArticleForm`实际上是非常简单的，仅包含了`title`和`body`两个字段。

```python
#blog/forms.py
from .models import Article
from django import forms

class ArticleForm(forms.ModelForm):
     class Meta:
         model = Article
         fields = ['title', 'body']
```

## 基于函数的视图和基于类的视图

Django提供了两种编写视图的方式: 基于函数的视图(Function Base View, FBV)和基于类的视图(Class Based View, CBV)。前面案例中的`index`，`article_detail`和`article_update`的方法都是基于函数的视图。函数视图的优点是比较直接，容易读者理解, 缺点是不便于继承和重用。

基于类的视图以`class`定义，而不是函数视图的`def`定义。使用类视图后可以将视图对应的不同请求方式以类中的不同方法来区别定义(get方法处理GET请求，post方法处理POST请求)，相对于函数视图逻辑更清晰，代码也有更高的复用性。

```python
from django.views.generic import View

class MyClassView(View):
    """类视图"""
    def get(self, request):
        """处理GET请求"""
        return render(request, 'register.html')

    def post(self, request):
        """处理POST请求"""
        return ...
```
**注意**：在URL配置文件中使用类视图时，需要使用`as_view()`将其伪装成方法：

```python
# blog/urls.py
from django.urls import path, re_path
from . import views
 
urlpatterns = [
    path('', views.MyClassView.as_view()),
]
```


## Django通用类视图

在实际Web开发过程中，我们对不同的数据或模型总是反复进行以下同样的操作，使用通用的类视图可以大大简化我们的代码量。

- 展示对象列表（比如所有用户，所有文章）
- 查看某个对象的详细信息（比如用户资料，比如文章详情)
- 通过表单创建某个对象（比如创建用户，新建文章）
- 通过表单更新某个对象信息（比如修改密码，修改文字内容）
- 用户填写表单提交后转到某个完成页面
- 删除某个对象

Django提供了很多通用的基于类的视图，来帮我们简化视图的编写。这些View与上述操作的对应关系如下:

- 展示对象列表（比如所有用户，所有文章）- `ListView`

- 展示某个对象的详细信息（比如用户资料，比如文章详情) - `DetailView`

- 通过表单创建某个对象（比如创建用户，新建文章）- `CreateView`

- 通过表单更新某个对象信息（比如修改密码，修改文字内容）- `UpdateView`

- 用户填写表单后转到某个完成页面 - `FormView`

- 删除某个对象 - `DeleteView`


上述常用通用视图一共有6个，前2个属于展示类视图(Display view), 后面4个属于编辑类视图(Edit view)。下面我们就来看下这些通用视图是如何工作的，如何简化我们代码的。

注意：如果你要使用Edit view，请务必在模型里里定义`get_absolute_url()`方法，否则会出现错误。这是因为通用视图在对一个对象完成编辑后，需要一个返回链接。`get_absolute_url()`可以为某个对象生成独一无二的url。

### ListView

`ListView`用来展示一个对象的列表。它只需要一个参数模型名称即可。比如我们希望展示所有文章列表，我们的`views.py`可以简化为:

```python
# Create your views here.
from django.views.generic import ListView
from .models import Article

class IndexView(ListView):
    model = Article
```

上述代码等同于:

```python
# 展示所有文章
def index(request):
    queryset = Article.objects.all()
    return render(request, 'blog/article_list.html', {"article_list": queryset})
```

尽管我们只写了一行`model = Article`, `ListView`实际上在背后做了很多事情：

- 提取了需要显示的对象列表或数据集`queryset: Article.objects.all()`
- 指定了用来显示对象列表的模板名称: 默认`app_name/model_name_list.html`, 即`blog/article_list.html`.
- 指定了内容对象名称(context object name):默认值`object_list`

你或许已经注意到了2个问题：需要显示的文章对象列表并没有按发布时间逆序排列，默认内容对象名称`object_list`也不友好。或许你也不喜欢默认的模板名字，还希望通过这个视图给模板传递额外的内容(比如现在的时间)。你可以轻易地通过重写`queryset`, `template_name`和`context_object_name`来完成ListView的自定义。

如果你还需要传递模型以外的内容，比如现在的时间，你还可以通过重写`get_context_data`方法传递额外的参数或内容。

```python
# Create your views here.
from django.views.generic import ListView
from .models import Article
from django.utils import timezone

class IndexView(ListView):

    queryset = Article.objects.all().order_by("-pub_date")
    template_name = 'blog/article_list.html'
    context_object_name = 'latest_articles'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['now'] = timezone.now()
        return context
```

如果上述的queryset还不能满足你的要求，比如你希望一个用户只看到自己发表的文章清单，你可以通过更具体的`get_queryset()`方法来返回一个需要显示的对象列表。

```python
# Create your views here.
from django.views.generic import ListView
from .models import Article
from django.utils import timezone

class IndexView(ListView):

    template_name = 'blog/article_list.html'
    context_object_name = 'latest_articles'

    def get_queryset(self):
        return Article.objects.filter(author=self.request.user).order_by('-pub_date')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['now'] = timezone.now()
        return context
```


### DetailView

`DetailView`用来展示一个具体对象的详细信息。它需要URL传递某个对象的具体参数（如id, pk, slug值）。本例中用来展示某篇文章详细内容的view可以简写为:

```python
# Create your views here.
from django.views.generic import DetailView
from .models import Article

class ArticleDetailView(DetailView):
    model = Article
```

`DetailView`默认的模板是`app/model_name_detail.html`,默认的内容对象名字`context_object_name`是model_name。本例中默认模板是`blog/article_detail.html`, 默认对象名字是`article`, 在模板里可通过 `{{ article.title }}`获取文章标题。

你同样可以通过重写`queryset`, `template_name`和`context_object_name`来完成DetailView的自定义。你还可以通过重写`get_context_data`方法传递额外的参数或内容。如果你指定了queryset, 那么返回的object是queryset.get(pk = id), 而不是model.objects.get(pk = id)。

```python
# Create your views here.
from django.views.generic import ListView，DetailView
from .models import Article
from django.utils import timezone

class ArticleDetailView(DetailView):

    queryset = Article.objects.all().order_by("-pub_date") # 一般不写
    template_name = 'blog/article_detail.html'
    context_object_name = 'article'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['now'] = timezone.now()
        return context
```

###  CreateView

`CreateView`一般通过某个表单创建某个对象，通常完成后会转到对象列表。比如一个最简单的文章创建CreateView可以写成：

```python
from django.views.generic.edit import CreateView
from .models import Article

class ArticleCreateView(CreateView):
    model = Article
    fields = ['title', 'body',]
```

CreateView默认的模板是`model_name_form.html,` 即`article_form.html`。这里CreateView还会根据`fields`自动生成表单字段。默认的context_object_name是`form`。模板代码如下图所示:

```html
# blog/article_form.html
{% raw %}
<form method="post">{% csrf_token %}
    {{ form.as_p }}
    <input type="submit" value="Save" />
</form>{% endraw %}
```

如果你不想使用默认的模板和默认的表单，你可以通过重写`template_name`和`form_class`来完成CreateView的自定义。

对于`CreateView`, 重写它的`form_valid`方法不是必需，但很有用。当用户提交的数据是有效的时候，执行该方法。你可以通过定义此方法做些别的事情，比如发送邮件，存取额外的数据。

```python
from django.views.generic.edit import CreateView
from .models import Article
from .forms import ArticleCreateForm

class ArticleCreateView(CreateView):
    model = Article
    template_name = 'blog/article_create_form.html'
    form_class = ArticleCreateForm

    def form_valid(self, form):
       form.do_sth()
       return super(ArticleCreateView, self).form_valid(form)
```

form_valid方法一个常见用途就是就是将创建对象的用户与model里的user结合（需要用户先登录再提交)。见下面例子。

```python
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic.edit import CreateView
from .models import Article

class ArticleCreate(LoginRequiredMixin, CreateView):
    model = Article
    fields = ['title', 'body']

    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)
```

### UpdateView

UpdateView一般通过某个表单更新现有对象的信息，更新完成后会转到对象详细信息页面。它需要URL提供访问某个对象的具体参数（如pk, slug值）。比如一个最简单的文章更新的UpdateView如下所示。

```python
from django.views.generic.edit import UpdateView
from .models import Article

class ArticleUpdateView(UpdateView):
    model = Article
    fields = ['title', 'body',]
```

UpdateView和CreateView很类似，比如默认模板都是`model_name_form.html`, 因此它们可以共用一个模板。但是区别有两点: 

- CreateView显示的表单是空表单，UpdateView中的表单会显示现有对象的数据。
- 用户提交表单后，CreateView转向对象列表，UpdateView转向对象详细信息页面。

你可以通过重写`template_name`和`form_class`来完成UpdateView的自定义。

- 本例中默认的模板是`article_form.html`, 你可以改为`article_update_form.html`。
- 虽然form_valid方法不是必需，但很有用。当用户提交的数据是有效的时候，你可以通过定义此方法做些别的事情，比如发送邮件，存取额外的数据。

```python
from django.views.generic.edit import UpdateView
from .models import Article
from .forms import ArticleUpdateForm

class ArticleUpdateView(UpdateView):
    model = Article
    template_name = 'blog/article_update_form.html'
    form_class = ArticleUpdateForm

    def form_valid(self, form):
       form.do_sth()
       return super(ArticleUpdateView, self).form_valid(form)
```
另一个进行UpdateView的常用自定义方法是`get_object`方法。比如你希望一个用户只能编辑自己发表的文章对象。当一个用户尝试编辑别人的文章时，返回http 404错误。这时候你可以通过更具体的`get_object()`方法来返回一个更具体的对象。代码如下:

```python
from django.views.generic.edit import UpdateView
from .models import Article
from .forms import ArticleUpdateForm

class ArticleUpdateView(UpdateView):
    model = Article
    template_name = 'blog/article_update_form.html'
    form_class = ArticleUpdateForm
 
    def get_object(self, queryset=None):
        obj = super().get_object(queryset=queryset)
        if obj.author != self.request.user:
            raise Http404()
        return obj
```


### FormView

FormView一般用来展示某个表单，而不是用于创建或更新某个模型对象。当用户输入信息未通过表单验证，显示错误信息。当用户输入信息通过表单验证提交后，跳到其它页面。使用FormView一般需要定义`template_name`, `form_class`和`success_url`.

见下面代码。

```python
# views.py - Use FormView
from myapp.forms import ContactForm
from django.views.generic.edit import FormView

class ContactView(FormView):
    template_name = 'contact.html'
    form_class = ContactForm
    success_url = '/thanks/'

    def form_valid(self, form):
        # This method is called when valid form data has been POSTed.
        # It should return an HttpResponse.
        form.send_email()
        return super().form_valid(form)
```

### DeleteView

DeleteView一般用来删除某个具体对象。它要求用户点击确认后再删除一个对象。使用这个通用视图，你需要定义模型的名称model和成功删除对象后的返回的URL。默认模板是`myapp/model_confirm_delete.html`。默认内容对象名字是model_name。本例中为article。

本例使用了默认的模板`blog/article_confirm_delete.html`，删除文章后通过`reverse_lazy`方法返回到index页面。

```python
from django.urls import reverse_lazy
from django.views.generic.edit import DeleteView
from .models import Article

class ArticleDelete(DeleteView):
    model = Article
    success_url = reverse_lazy('index')
```

模板内容如下:

```html
# blog/article_confirm_delete.html
{% raw %}
<form method="post">{% csrf_token %}
    <p>Are you sure you want to delete "{{ article }}"?</p>
    <input type="submit" value="Confirm" />
</form>{% endraw %}
```

## 小结

本章我们详细介绍了Django的视图(View)是如何工作的，并展示了如何使用基于函数的视图和通用类视图(`ListView`, `DetailView`, `CreateView`, `UpdateView`, `DeleteView`)编写基本的增删改查视图。在Django进阶部分我们将介绍更多视图编写技巧。下章我们将讲解模板语言, 常见的模板标签和过滤器以及如何正确配置模板文件。

原创不易，转载请注明来源。我是大江狗，一名Django技术开发爱好者。您可以通过搜索【<a href="https://blog.csdn.net/weixin_42134789">CSDN大江狗</a>】、【<a href="https://www.zhihu.com/people/shi-yun-bo-53">知乎大江狗</a>】和搜索微信公众号【Python Web与Django开发】关注我！

![Python Web与Django开发](../../assets/images/django.png)

