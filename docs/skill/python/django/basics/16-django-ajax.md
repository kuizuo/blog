---
layout: default
title:  Django与Ajax交互
parent: 大江狗的Django入门教程
nav_order: 16
---

# Django与Ajax交互


## 目录


1. TOC
{:toc}

---
Django前端模板向后端发送POST请求主要有两种方式：form表单和ajax请求。本文将详细介绍Django与Ajax的交互方式，如何通过csrftoken认证，并提供了两个具体示例。


## 前后端传输数据的编码格式

前后端传输数据的编码格式主要有三种, 本文接下来将详细演示。

```text
urlencoded
formdata
json
```

## Ajax提交urlencoded格式数据
Ajax给后台发送数据的默认编码格式是urlencoded，比如`username=abcde&password=123456`的形式。Django后端拿到符合urlencoded编码格式的数据都会自动帮你解析分装到`request.POST`中,与form表单提交的数据相同。

下面两种方式是等同的。

```javascript
{% raw %}//手动构造数据data
$("#btnSubmit").click(function () {
    $.ajax({
        url: '/login/', //也可以反向解析{% url 'login' %}
        type: 'post',
        data: {
            'username': $("#id_username").val(),
            'password': $('#id_password').val()
        },
        // 上面data为提交数据，下面data形参指代的就是异步提交的返回结果data
        success: function (data){
            
        }
    })；
}；
                    
// .serialize() 方法可将<input>, <textarea> 以及 <select>表单序列化
// 成urlencoded格式数据
                      
$("#btnSubmit").click(function () {
    let data = $("#loginForm").serialize();
    $.ajax({
        url: "/login/", //别忘了加斜杠
        type: $("#loginForm").attr('method'),
        data: data,
        // 下面data形参指代的就是异步提交的返回结果data
        success: function (data) {
         
        }
    });
}); {% endraw %}
```

## Ajax通过FormData上传文件
Ajax上传文件需要借助于js内置对象`FormData`，另外上传文件时表单千万别忘了加`enctype="multipart/form-data"`属性。


```javascript
{% raw %}
//案例1，点击submi上传文件
$("#submitFile").click(function () {
    let formData = new FormData($("#upload-form"));
    $.ajax({
       url:"/upload/",//也可以写{% url 'upload' %}
       type:"post",
       data:formData,
       //这两个要必须写
       processData:false,  //不预处理数据  因为FormData 已经做了
       contentType:false,  //不指定编码了 因为FormData 已经做了
       success:function(data){
             console.log(data);
       }
    });
});
                       
//案例2,同时上传文件并提交其它数据
$("#submitFile").click(function () {
    //js取到文件,一定要加0
    let myfile = $("#id_file").files[0];
    //生成一个FormData对象
    let formdata = new FormData();
    //加其它值
    formdata.append('name', $("#id_name").val());
    //加文件
    formdata.append('myfile', myfile);
    $.ajax({
        url: '/upload/', //url别忘了加/杠
        type: 'post',
        //这两个要必须写
        processData:false,  //不预处理数据  因为FormData 已经做了
        contentType:false,  //不指定编码了 因为FormData 已经做了
        data: formdata,
        success: function (data) {
            console.log(data);
        }
    });
}); {% endraw %}
```

##  Ajax提交Json格式数据
前后端传输数据的时候一定要确保声明的编码格式跟数据真正的格式是一致的。如果你通过Ajax发送Json格式数据给Django后端，请一定注意以下三点：

1. `contentType`参数指定成`application/json`;

2. 数据是真正的json格式数据；

3. Django后端不会帮你处理json格式数据需要你自己去`request.body`获取并处理。

```javascript
$("#submitBtn").click(function () {
    var data_obj={'name':'abcdef','password':123456};//Javascript对象
    $.ajax({
        url:'',
        type:'post',
        contentType:'application/json',  //一定要指定格式 contentType
        data:JSON.stringify(data_obj),    //转换成json字符串格式
        success:function (data) {
            console.log(data)
        }
    });
});
```

## Ajax发送POST请求时如何通过CSRF认证

```javascript
{% raw %}
// 第一种方式直接在发送数据中加入csrfmiddlewaretoken
$("#btn").on("click",function () {
    $.ajax({
        url:"/some_url/",
        type:"POST",
        data:{
            //写在模板中，才会被渲染
            'csrfmiddlewaretoken': {{ csrf_token }}, 
            //其它数据
            'username': $("#id_username").val(),
            'password': $('#id_password').val()       
        },
        success:function (data) {
    }
});
});
 
//通过jquery选择器获取csrfmiddlewaretoken
$("#btn").on("click",function () {
    $.ajax({
        url:"/some_url/",
        type:"POST",
        data:{
            'csrfmiddlewaretoken':$('[name="csrfmiddlewaretoken"]').val(),
            'username': $("#id_username").val(),
            'password': $('#id_password').val()       
        },
        success:function (data) {
            
        }
    });
});
 
//使用jquery.cookie.js调用请求头cookie中的csrftoken
<script src="/static/jquery.cookie.js"> 
<script>
     $("#btn").on("click",function () {
     $.ajax({
        url:"/some_url/",
        type:"POST",
        headers:{"X-CSRFToken":$.cookie('csrftoken')},
        data:$("#form1").serialize()
    });
   })
</script>
{% endraw %}
```

## Django Ajax案例1：联动下例菜单

联动下拉菜单是Web开发中一个被经常使用的应用。比如当你从一个列表从选择一个国家的时候，联动下拉菜单会同步显示属于该国家所有城市列表供用户选择。今天我们就教你如何使用Django+Ajax生成联动下拉菜单。

我们的模型如下所示：

```python
class Country(models.Model):
    name = models.CharField(verbose_name="国家", max_length=50)

    def __str__(self):
        return self.name


class City(models.Model):
    name = models.CharField(verbose_name="城市", max_length=50)
    country = models.ForeignKey(Country, on_delete=models.CASCADE, verbose_name="国家",)

    def __str__(self):
        return self.name
```

我们的模板如下所示，表单中对应国家和城市下拉菜单的DOM元素id分别为`id_country`和`id_city`。当用户选择国家后，ajax会携带国家的id值向后台发送请求获得当前国家的所有城市清单，并在前端渲染显示。

```html
{% raw %}{% block content %}
<h2>创建用户 - 联动下拉菜单</h2>
<form method="post" class="form-horizontal" role='form' action="">
  {% csrf_token %}
  {{ form.as_p }}
  <button type="submit" class="btn btn-primary">Submit</button>
</form>
{% endblock %}

<script src="https://code.jquery.com/jquery-3.1.0.min.js"></script>
<script>
    $("#id_country").change(function() {
      var country_id = $(this).val();

      $.ajax({
        url: '/ajax/load_cities/',
        data: {
          'country_id': country_id
        },
        type: 'GET',
        dataType: 'json',
        success: function (data) {
            var content='';
            //对结果进行遍历，生成下拉菜单
            $.each(data, function(i, item){
                  content+='<option value='+item.id+'>'+item.name+'</option>'
                });
            $('#id_city').html(content)
        },

      });
    });
  </script>{% endraw %}
```

Django负责处理视图Ajax请求的视图函数如下所示：

```python
def ajax_load_cities(request):
    if request.method == 'GET':
        country_id = request.GET.get('country_id', None)
        if country_id:
            data = list(City.objects.filter(country_id=country_id).values("id", "name"))
            return JsonResponse(data, safe=False)
```

## Django Ajax案例2：Ajax上传文件

前端模板及js文件如下所示, 请注意我们是如何在表单中加入了`enctype`属性，如何使用`FormData`上传文件，并解决了`csrftoken`问题的。

```html
{% raw %}{% block content %}
<form action="" method="post" enctype="multipart/form-data" id="form">
    <ul class="errorlist"></ul>
    {% csrf_token %}
{{ form.as_p }}
 <input type="button" class="btn btn-info form-control" value="submit" id="btn" />
</form>
<table class="table table-striped" id="result">
</table>
{% endblock %}

{% block js %}
<script src=" https://cdn.jsdelivr.net/jquery.cookie/1.4.1/jquery.cookie.min.js ">
</script>
<script>
var csrftoken = $.cookie('csrftoken');
function csrfSafeMethod(method) {
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
$(document).ready(function(){
   $('#btn').click(function(e){
        e.preventDefault();
        // 构建FormData对象
        var form_data = new FormData();
        form_data.append('file', $('#id_file').files[0]);
        $.ajax({
        url: '/file/ajax_upload/',
        data: form_data,
        type: 'POST',
        dataType: 'json',
        // 告诉jQuery不要去处理发送的数据, 发送对象。
        processData : false,
        // 告诉jQuery不要去设置Content-Type请求头
        contentType : false,
        // 获取POST所需的csrftoken
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }},
        success: function (data) {
            if(data['error_msg']) {
                var content = '<li>'+ data['error_msg'] + '</li>';
                $('ul.errorlist').html(content);
            }
            else
            {
            var content= '<thead><tr>' +
            '<th>Name and URL</th>' +
            '<th>Size</th>' +
            '</tr></thead><tbody>';
             $.each(data, function(i, item) {
                  content = content +
                  '<tr><td>' +
                  "<a href= ' " +
                  item['url'] +
                  " '> " +
                  item['url'] +
                  '</a></td><td>' +
                  item['size'] +
                  '</td><td><tr>'
                });
             content = content + "</tbody>";
             $('#result').html(content);
             }
           },
        });
   });
 });
  </script>
{% endblock %}{% endraw %}
```

Django负责处理视图Ajax请求的视图函数如下所示：

```python
# handling AJAX requests
def ajax_upload(request):
    if request.method == "POST":
        form = FileUploadModelForm(data=request.POST, files=request.FILES)
        if form.is_valid():
            form.save()
            # Obtain the latest file list
            files = File.objects.all().order_by('-id')
            data = []
            for file in files:
                data.append({
                    "url": file.file.url,
                    "size": filesizeformat(file.file.size),
                    })
            return JsonResponse(data, safe=False)
        else:
            data = {'error_msg': "Only jpg, pdf and xlsx files are allowed."}
            return JsonResponse(data)
    return JsonResponse({'error_msg': 'only POST method accpeted.'})
```

原创不易，转载请注明来源。我是大江狗，一名Django技术开发爱好者。您可以通过搜索【<a href="https://blog.csdn.net/weixin_42134789">CSDN大江狗</a>】、【<a href="https://www.zhihu.com/people/shi-yun-bo-53">知乎大江狗</a>】和搜索微信公众号【Python Web与Django开发】关注我！

![Python Web与Django开发](../../assets/images/django.png)

