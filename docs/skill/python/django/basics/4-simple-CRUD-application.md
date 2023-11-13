---
layout: default
title: Django CRUD小应用
parent: 大江狗的Django入门教程
nav_order: 4
---

# 一个任务管理CRUD小应用


## 目录


1. TOC
{:toc}

---

很多人说Web后台开发人员每天的工作就是对数据库数据进行增删改查(CRUD)，可见CRUD开发的重要性。今天我将利用Django基于函数的视图编写一个任务管理小应用，实现创建(**Create**)一个任务，查看(**Retrieve**)任务清单和单个任务详情，更新(**Update**)一个任务和删除(**Delete**)一个任务。


本例中我们只讲述核心逻辑，不浪费时间在前端样式上。文末有GitHub源码地址，里面同时包含了函数视图和基于类的视图, 具体演示效果如下所示：

![Django CRUD](2-installation-use.assets/aHR0cHM6Ly9tbWJpei5xcGljLmNuL21tYml6X2dpZi9idWFGTEZLaWNSb0RUQzlhMzBnRHNJamhyaDZVZW81UUFtdlQ0dWxKU2liczBxenFyV0I4dWhDZUlsdTJWTHdDQjRzRHVLY0VHOUF6Q0RHNmhWcVFpYU1LZy82NDA)![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

## 第一步：创建tasks应用，加入INSTALLED_APPS

本例假设你已经有了一个`mysite`的Django项目。我们首先使用 `python manage.py startapp tasks` 创建一个名为"tasks"的app，并把它计入到`settings.py`的INSTALLED_APPS中去。

```python
# mysite/settings.py
INSTALLED_APPS = [
     'django.contrib.admin',
     'django.contrib.auth',
     'django.contrib.contenttypes',
     'django.contrib.sessions',
     'django.contrib.messages',
     'django.contrib.staticfiles',
     'tasks',
 ]
```

然后把app下的urls路径添加到项目文件夹的urls.py里去。

```python
 from django.contrib import admin
 from django.urls import path, include

 urlpatterns = [
     path('admin/', admin.site.urls),
     path('tasks/', include('tasks.urls'))
 ]
```

## 第二步：创建Task模型及其关联表单

我们的Task模型非常简单，仅包含name和status两个字段。我们还使用ModelForm类创建了TaskForm，我们在创建任务或更新任务时需要用到这个表单。

```python
# tasks/models.py
 from django.db import models

 class Status(models.TextChoices):
     UNSTARTED = 'u', "Not started yet"
     ONGOING = 'o', "Ongoing"
     FINISHED = 'f', "Finished"


 class Task(models.Model):
     name = models.CharField(verbose_name="Task name", max_length=65, unique=True)
     status = models.CharField(verbose_name="Task status", max_length=1, choices=Status.choices)

     def __str__(self):
         return self.name

 # tasks/forms.py
 from .models import Task
 from django import forms

 class TaskForm(forms.ModelForm):

     class Meta:
         model = Task
         fields = "__all__"
```

## 第三步：编写路由URLConf及视图

我们需要创建5个urls, 对应5个函数视图。这是因为对于Retrieve操作，我们需要编写两个函数视图，一个用户获取任务列表，一个用于获取任务详情。对于`task_detail`, `task_update`和`task_delete`这个三个视图函数，我们还需要通过urls传递任务id或pk参数，否则它们不知道对哪个对象进行操作。

```python
# tasks/urls.py
 from django.urls import path, re_path
 from . import views

 # namespace
 app_name = 'tasks'

 urlpatterns = [
     # Create a task
     path('create/', views.task_create, name='task_create'),

     # Retrieve task list
     path('', views.task_list, name='task_list'),

     # Retrieve single task object
     re_path(r'^(?P<pk>\d+)/$', views.task_detail, name='task_detail'),

     # Update a task
     re_path(r'^(?P<pk>\d+)/update/$', views.task_update, name='task_update'),

     # Delete a task
     re_path(r'^(?P<pk>\d+)/delete/$', views.task_delete, name='task_delete'),
 ]
```

下面5个函数视图代码是本应用的核心代码，请仔细阅读并去尝试理解每一行代码。

```python
# tasks/views.py

 from django.shortcuts import render, redirect, get_object_or_404
 from django.urls import reverse
 from .models import Task
 from .forms import TaskForm
 
 # Create a task
 def task_create(request):
     # 如果用户通过POST提交，通过request.POST获取提交数据
     if request.method == "POST":
         # 将用户提交数据与TaskForm表单绑定
         form = TaskForm(request.POST)
         # 表单验证，如果表单有效，将数据存入数据库
         if form.is_valid():
             form.save()
             # 跳转到任务清单
             return redirect(reverse("tasks:task_list"))
     else:
         # 否则空表单
         form = TaskForm()
     return render(request, "tasks/task_form.html", { "form": form, })

 # Retrieve task list
 def task_list(request):
     # 从数据库获取任务清单
     tasks = Task.objects.all()
     # 指定渲染模板并传递数据
     return render(request, "tasks/task_list.html", { "tasks": tasks,})

 # Retrieve a single task
 def task_detail(request, pk):
     # 从url里获取单个任务的pk值，然后查询数据库获得单个对象
     task = get_object_or_404(Task, pk=pk)
     return render(request, "tasks/task_detail.html", { "task": task, })

 # Update a single task
 def task_update(request, pk):
     # 从url里获取单个任务的pk值，然后查询数据库获得单个对象实例
     task_obj = get_object_or_404(Task, pk=pk)
     if request.method == 'POST':
         form = TaskForm(instance=task_obj, data=request.POST)
         if form.is_valid():
             form.save()
             return redirect(reverse("tasks:task_detail", args=[pk,]))
     else:
         form = TaskForm(instance=task_obj)
     return render(request, "tasks/task_form.html", { "form": form, "object": task_obj})


 # Delete a single task
 def task_delete(request, pk):
     # 从url里获取单个任务的pk值，然后查询数据库获得单个对象
     task_obj = get_object_or_404(Task, pk=pk)
     task_obj.delete() # 删除然后跳转
     return redirect(reverse("tasks:task_list"))
```

## 第四步：编写模板

虽然我们有5个urls，但我们只需要创建3个模板:`task_list.html`, `task_detail.html` 和`task_form.html。` 最后一个模板由`task_create` 和`task_update` 视图函数共享。我们在模板中对实例对象进行判断，如果对象已存在则模板对于更新任务，否则是创建任务。task_delete视图不需要模板。

```python
{% raw %}
 # tasks/templates/tasks/task_list.html
 <!DOCTYPE html>
 <html lang="en">
 <head>
     <meta charset="UTF-8">
     <title>Task List</title>
 </head>
 <body>
 <h3>Task List</h3>
 {% for task in tasks %}
     <p>{{ forloop.counter }}. {{ task.name }} - {{ task.get_status_display }}
         (<a href="{% url 'tasks:task_update' task.id %}">Update</a> |
         <a href="{% url 'tasks:task_delete' task.id %}">Delete</a>)
     </p>
 {% endfor %}
 <p> <a href="{% url 'tasks:task_create' %}"> + Add A New Task</a></p>
 </body>
 </html>


 # tasks/templates/tasks/task_detail.html
 <!DOCTYPE html>
 <html lang="en">
 <head>
     <meta charset="UTF-8">
     <title>Task Detail</title>
 </head>
 <body>
 <p> Task Name: {{ task.name }} | <a href="{% url 'tasks:task_update' task.id %}">Update</a> |
     <a href="{% url 'tasks:task_delete' task.id %}">Delete</a>
 </p>
 <p> Task Status: {{ task.get_status_display }} </p>
 <p> <a href="{% url 'tasks:task_list' %}">View All Tasks</a> |
     <a href="{% url 'tasks:task_create'%}">New Task</a>
 </p>
 </body>
 </html>


 # tasks/templates/tasks/task_form.html
 <!DOCTYPE html>
 <html lang="en">
 <head>
     <meta charset="UTF-8">
     <title>{% if object %}Edit Task {% else %} Create New Task {% endif %}</title>
 </head>
 <body>
 <h3>{% if object %}Edit Task {% else %} Create New Task {% endif %}</h3>
     <form action="" method="post" enctype="multipart/form-data">
         {% csrf_token %}
         {{ form.as_p }}
         <p><input type="submit" class="btn btn-success" value="Submit"></p>
     </form>
 </body>
 </html> 
{% endraw %}
```

## 第五步：运行项目，查看效果

运行如下命令，访问http://127.0.0.1:8000/tasks/就应该看到文初效果了。

```bash
 python manage.py makemigrations
 python manage.py migrate
 python manage.py runserver
```

## GitHub源码地址

本项目源码地址，里面同时包含了函数视图和基于类的视图。

https://github.com/shiyunbo/django-crud-example

## 小结

本例中我们使用了函数视图(functional-based views, FBV)编写了一个任务管理的CRUD小应用，后面我们将使用基于类的视图(class-based views, CBV)重写本例演示代码。

接下来几章我们将详细介绍模型、视图、URL的配置以及模板的基础知识，欢迎关注。

原创不易，转载请注明来源。我是大江狗，一名Django技术开发爱好者。您可以通过搜索【<a href="https://blog.csdn.net/weixin_42134789">CSDN大江狗</a>】、【<a href="https://www.zhihu.com/people/shi-yun-bo-53">知乎大江狗</a>】和搜索微信公众号【Python Web与Django开发】关注我！

![Python Web与Django开发](../../assets/images/django.png)
