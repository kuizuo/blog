---
layout: default
title: Django表单设计与使用
parent: 大江狗的Django入门教程
nav_order: 10
---

# Django表单设计、验证与使用


## 目录


1. TOC
{:toc}

---
在web开发里表单的使用必不可少。表单用于让用户提交数据或上传文件，也用于用户编辑已有数据。Django的表单Form类的作用是把用户输入的数据转化成Python对象格式，便于后续操作（比如存储、修改)。本章将介绍如何自定义表单类，如何在视图和模板中使用表单以及如何自定义表单验证。


## 自定义表单类
Django提供了两种自定义表单的方式：继承`Form`类和`ModelForm`类。前者你需要自定义表单中的字段，后者可以根据Django模型自动生成表单，如下所示：

```python
# app/forms.py
# 自定义表单字段
from django import forms
from .models import Contact

class ContactForm1(forms.Form):
    name = forms.CharField(label="Your Name", max_length=255)
    email = forms.EmailField(label="Email address")

# 根据模型创建
class ContactForm2(forms.ModelForm):
    
    class Meta:
        model = Contact
        fields = ('name', 'email',)

```
注意：Django模型里用`verbose_name`来给字段添加一个别名或描述, 而表单用的是`label`。

自定义的表单类一般位于app目录下的`forms.py`，这样方便集中管理表单。如果要使用上述表单，我们可以在视图里`views.py`里把它们像模型一样`import`进来直接使用。

### 自定义字段错误信息
对于每个字段你可以设置其是否为必需，最大长度和最小长度。你还可以针对每个字段自定义验证错误信息，见下面代码。
```python
from django import forms

class LoginForm(forms.Form):  
    username = forms.CharField(
        required=True,
        max_length=20,
        min_length=6,
        error_messages={
            'required': '用户名不能为空',
            'max_length': '用户名长度不得超过20个字符',
            'min_length': '用户名长度不得少于6个字符',
        }
    )
    password = forms.CharField(
        required=True,
        max_length=20,
        min_length=6,
        error_messages={
            'required': '密码不能为空',
            'max_length': '密码长度不得超过20个字符',
            'min_length': '密码长度不得少于6个字符',
        }
    )
```
对于基继承`ModelForm`类的表单, 我们可以在`Meta`选项下widget中来自定义错误信息，如下面代码所示:

```python
from django.forms import ModelForm, Textarea
from myapp.models import Author

class AuthorForm(ModelForm):
    class Meta:
        model = Author
        fields = ('name', 'title', 'birth_date')
        widgets = {
            'name': Textarea(attrs={'cols': 80, 'rows': 20}),  # 关键是这一行
        }
        labels = {
            'name': 'Author',
        }
        help_texts = {
            'name': 'Some useful help text.',
        }
        error_messages = {
            'name': {
                'max_length': "This writer's name is too long.",
            },
        }
```

### 自定义表单输入widget

Django表单的每个字段你都可以选择你喜欢的输入`widget`，比如多选，复选框。你还可以定义每个widget的css属性。如果你不指定，Django会使用默认的widget，有时比较丑。

比如下面这段代码定义了表单姓名字段的输入控件为Textarea，还指定了其样式css。

```python
from django import forms

class ContactForm(forms.Form):
    name = forms.CharField(
        max_length=255,
        widget=forms.Textarea(
            attrs={'class': 'custom'},
        ),
    )
```

设置widget可以是你的表单大大美化，方便用户选择输入。比如下面案例里对年份使用了`SelectDateWidget`，对课程使用`RadioSelect`, 颜色则使用了复选框`CheckboxSelectMultiple`。

```python
from django import forms

BIRTH_YEAR_CHOICES = ('1980', '1981', '1982')
COLORS_CHOICES = (
    ('blue', 'Blue'),
    ('green', 'Green'),
    ('black', 'Black'),
)

class SimpleForm(forms.Form):
    birth_year = forms.DateField(
        widget=forms.SelectDateWidget(years=list(BIRTH_YEAR_CHOICES))
    )
    favorite_colors = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple,
        choices=list(COLORS_CHOICES),
    )
```


## 表单实例化与初始化

定义好一个表单类后，你就可以对其进行实例化或初始化。下面方法可以实例化一个空表单，但里面没有任何数据，可以通过 `{% raw %}{{ form }}{% endraw %}`在模板中渲染。

```python
form = ContactForm() # 空表单
```
有时我们需要对表单设置一些初始数据，我们可以通过`initial`方法或设置`default_data`，如下所示。

```python
# initial方法初始化
form = ContactForm(
    initial={
        'name': 'First and Last Name',
    },)

# default_data默认值
default_data = {'name': 'John', 'email': 'someone@hotmail.com', }
form = ContactForm(default_data)
```

用户提交的数据可以通过以下方法与表单结合，生成与数据结合过的表单(Bound forms)。Django只能对Bound forms进行验证。

```python
form = ContactForm(data=request.POST, files=request.FILES)
```

其编辑修改类应用场景中，我们还要给表单提供现有对象实例的数据，而不是渲染一张空表单，这时我们可这么做。该方法仅适用于由模型创建的`ModelForm`，而不适用于自定义的表单l。
```python
contact = Contact.objects.get(id=1)
form =  ContactForm(instance = contact, data=request.POST)
```

## 表单的使用

Django的视图一般会将实例化/初始化后的表单以`form`变量传递给模板，在模板文件中我们可以通过`{% raw %}{{ form.as_p }}, {{ form.as_li }}, {{ form.as_table }} {% endraw %}`的方式渲染表单。如果你想详细控制每个字段field的格式，你可以采取以下方式。

```html
{% raw %}
{% block content %}
<div class="form-wrapper">
   <form method="post" action="" enctype="multipart/form-data">
      {% csrf_token %}
      {% for field in form %}
           <div class="fieldWrapper">
        {{ field.errors }}
        {{ field.label_tag }} {{ field }}
        {% if field.help_text %}
             <p class="help">{{ field.help_text|safe }}</p>
        {% endif %}
           </div>
        {% endfor %}
      <div class="button-wrapper submit">
         <input type="submit" value="Submit" />
      </div>
   </form>
</div>
{% endblock %} {% endraw %}
```

## 表单实际使用案例

我们现在需要设计一个表单让用户完成注册。我们先在app目录下新建`forms.py`, 然后创建一个`RegistrationForm`, 代码如下:

```python
from django import forms
from django.contrib.auth.models import User

class RegistrationForm(forms.Form):
    username = forms.CharField(label='Username', max_length=50)
    email = forms.EmailField(label='Email',)
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password Confirmation', widget=forms.PasswordInput)
```

当然你也可以不用新建`forms.py`而直接在html模板里写表单，但我并不建议这么做。用forms.py的好处显而易见: 

- 所有的表单在一个文件里，非常便于后期维护，比如增添或修订字段。
- `forms.py`可通过`clean`方法自定义表单验证，非常便捷（见后文）。

接下来我们要在视图`views.py`中使用这个表单，并将其向指定模板传递。

```python
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from .forms import RegistrationForm
from django.http import HttpResponseRedirect

def register(request):
    if request.method == 'POST':
        # 将用户POST提交数据与表单结合，准备验证
        form = RegistrationForm(request.POST) 
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password2']
            # 使用内置User自带create_user方法创建用户，不需要使用save()
            user = User.objects.create_user(username=username, password=password, email=email)
            # 如果直接使用objects.create()方法后不需要使用save()
            return HttpResponseRedirect("/accounts/login/")
    else:
        form = RegistrationForm()

    return render(request, 'users/registration.html', {'form': form})
```

模板是`registration.html`代码很简单，如下所示。如果你需要通过表单上传图片或文件，一定不要忘了给form加`enctype="multipart/form-data"`属性。

```html
{% raw %}
<form action=”.” method=”POST”>
{{ form.as_p }}
</form>{% endraw %}
```

我们来看下`RegistrationForm`是怎么工作的:

- 当用户通过POST方法提交表单，我们将提交的数据与`RegistrationForm`结合，然后验证表单。
- 如果表单数据有效，我们先用Django User模型自带的`create_user`方法创建user对象。
- 如果用户注册成功，我们通过`HttpResponseRedirect`方法转到登陆页面。
- 如果用户没有提交表单或不是通过POST方法提交表单，我们转到注册页面，渲染一张空表单。

** 提示 **：本例的`RegistrationForm`是自定义的表单，表单验证通过后我们显示地通过`form.cleaned_data`获取验证后的数据，然后手动地存入数据库。如果你的表单是通过继承`ModelForm`创建的，你可以直接通过`form.save()`方法将验证过的表单数据存入数据库。

```python
if form.is_valid():
    form.save()
```

## 表单的验证

每个forms类可以通过`clean`方法自定义表单验证。如果你只想对某些字段进行验证，你可以通过`clean_字段名`方式自定义表单验证。如果用户提交的数据未通过验证，会将错误信息呈现给用户。如果用户提交的数据有效`form.is_valid()`，则会将数据存储在`cleaned_data`字典里。

在上述用户注册的案例里，我们在RegistrationForm通过clean方法添加了用户名验证，邮箱格式验证和密码验证。代码如下。

```python
from django import forms
from django.contrib.auth.models import User
import re

def email_check(email):
    pattern = re.compile(r"\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?")
    return re.match(pattern, email)

class RegistrationForm(forms.Form):
    username = forms.CharField(label='Username', max_length=50)
    email = forms.EmailField(label='Email',)
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password Confirmation', widget=forms.PasswordInput)

    # 自定义验证方法
    def clean_username(self):
        username = self.cleaned_data.get('username')

        if len(username) < 6:
            raise forms.ValidationError("Your username must be at least 6 characters long.")
        elif len(username) > 50:
            raise forms.ValidationError("Your username is too long.")
        else:
            user = User.objects.filter(username__exact=username).first()
            if user.exists():
                raise forms.ValidationError("Your username already exists.")

        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')

        if email_check(email):
            filter_result = User.objects.filter(email__exact=email)
            if len(filter_result) > 0:
                raise forms.ValidationError("Your email already exists.")
        else:
            raise forms.ValidationError("Please enter a valid email.")

        return email

    def clean_password1(self):
        password1 = self.cleaned_data.get('password1')

        if len(password1) < 6:
            raise forms.ValidationError("Your password is too short.")
        elif len(password1) > 20:
            raise forms.ValidationError("Your password is too long.")

        return password1

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Password mismatch. Please enter again.")

        return password2
```

## 通用类视图里使用表单

在Django基于类的视图(Class Based View)里使用表单也非常容易，你可以通过`model + fields`的方式定义或直接通过`form_class`设置自定义的表单类。下面是一个创建一篇新文章的例子，两种方式均可。

```python
from django.views.generic.edit import CreateView
from .models import Article
from .forms import ArticleForm

# 方式一: 通过model和fields定义表单
class ArticleCreateView(CreateView):
    model = Article
    fields = ['title', 'body']
    template_name = 'blog/article_form.html'

# 方式二：使用form_class
class ArticleCreateView(CreateView):
    model = Article
    form_class = ArticleForm
    template_name = 'blog/article_form.html'
```

## Formset的使用

有的时候用户需要在1个页面上使用多个表单，比如一次性提交添加多本书的信息，这时我们可以使用formset。这是一个表单的集合。

创建一个Formset我们可以这么做:

```python
from django import forms

class BookForm(forms.Form):
    name = forms.CharField(max_length=100)
    title = forms.CharField()
    pub_date = forms.DateField(required=False)

# forms.py - build a formset of books
from django.forms import formset_factory
from .forms import BookForm

# extra: 额外的空表单数量
# max_num: 包含表单数量（不含空表单)
BookFormSet = formset_factory(BookForm, extra=2, max_num=1)
```

在视图文件`views.py`里，我们可以像使用form一样使用`formset`.

```python
# views.py - formsets example.
from .forms import BookFormSet
from django.shortcuts import render

def manage_books(request):
    if request.method == 'POST':
        formset = BookFormSet(request.POST, request.FILES)
        if formset.is_valid():
            # do something with the formset.cleaned_data
            pass
    else:
        formset = BookFormSet()
    return render(request, 'manage_books.html', {'formset': formset})
```

在模板里也可以使用formset。

```html
{% raw %}
<form action=”.” method=”POST”>
{{ formset }}
</form>{% endraw %}
```

## 小结

本章总结了如何自定义表单，如何在视图和模板中使用它们，以及如何自定义表单验证。在表单进阶篇，我们将详细介绍表单的美化以及formset的使用。下章我们将介绍Django的自带管理后台(admin)及如何使用它。

原创不易，转载请注明来源。我是大江狗，一名Django技术开发爱好者。您可以通过搜索【<a href="https://blog.csdn.net/weixin_42134789">CSDN大江狗</a>】、【<a href="https://www.zhihu.com/people/shi-yun-bo-53">知乎大江狗</a>】和搜索微信公众号【Python Web与Django开发】关注我！

![Python Web与Django开发](../../assets/images/django.png)

