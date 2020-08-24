---
title: Express使用教程
date: 2020-08-21
tags:
 - node 
 - Express
categories: 
 - Node
---

# Express

`npm i -g express` 一般来说都是全局安装  
`npm i -g express-generator` 然后还要在安装脚手架一个环境变量的 

创建了一个名为 myapp 的 Express 应用，并使用ejs模板引擎

 `express --view=ejs myapp`
此时还需要进入myapp，并安装依赖

    cd myapp
    npm install

myapp文件夹下的文件结构；

    bin: 启动目录 里面包含了一个启动文件 www 默认监听端口是 3000 (直接node www执行即可)
    node_modules：依赖的模块包
    public：存放静态资源
    routes：路由操作
    views：存放ejs模板引擎
    app.js：主文件
    package.json：项目描述文件

**在Windows 下，使用以下命令启Express应用：**

```
set DEBUG=app:* '&' npm start
```

## 数据交互

### get请求

前台的get请求 `http://localhost:8080/login?goods1=0001&goods2=0002`
后台响应通过 `req.query` 可以获取到数据 如

    req.query.goods1
    req.query.goods2

### post请求

form表单进行post请求，enctype属性一般设置为“application/x-www-form-urlencoded”，如果设置成multipart/form-data，则多用于文件上传，如下：

    <form action="#" method="post" enctype="application/x-www-form-urlencoded">
    </form>

express需要设置解析body中间件 !!!

    app.use(express.urlencoded())

`req.body` 即可获取data属性对象

### 中间件

#### 应用层中间件

应用级中间键绑定到app对象使用app.use和app. METHOD()-需要处理http请求的方法，例如GET、PUT、POST，将之前的get或者post替换为use就行。

//匹配路由之前的操作
app.use(function(req, res, next()){

    console.log("访问之前");

}); 

这时我们会发现http://localhost:8080/地址一直在加载，但命令行里显示了“访问之前”，说明程序并不会同步执行，如果使用next来是路由继续向下匹配，那么就能又得到主页数据了：

正常写法
//匹配路由之前的操作
app.use(function(req, res, next){

    console.log("访问之前");
    
    next(); 

}); 

#### 路由中间件

路由级中间件和应用级中间件类似，只不过他需要绑定 `express.Router();`
    var router = express.Router()

在匹配路由时，我们使用 `router.use()` 或 `router.VERB()` , 路由中间件结合多次callback可用于用户登录及用户状态检测。

``` javascript
const express = require("express");
var app = express();
var router = express.Router();​
router.use("/", function(req, res, next) {
    console.log("匹配前");
    next();
});​
router.use("/user", function(req, res, next) {
    console.log("匹配地址：", req.originalUrl);
    next();
}, function(req, res) {
    res.send("用户登录");
});​
app.use("/", router);​
app.listen(8080);
```

> 总之在检测用户登录和引导用户应该访问哪个页面是，路由中间件绝对好用。

#### 错误处理中间件

顾名思义，它是指当我们匹配不到路由时所执行的操作。错误处理中间件和其他中间件基本一样，只不过其需要开发者提供4个自变量参数。

``` js
app.use((err, req, res, next) => {
    res.sendStatus(err.httpStatusCode).json(err);
});
```

一般情况下，我们把错误处理放在最下面，这样我们即可对错误进行集中处理。

``` js
const express = require("express");​
var app = express();​
app.get("/", function(req, res, next) {

    const err = new Error('Not Found');
    res.send("主页");
    next(err);

});​
app.use("/user", function(err, req, res, next) {
    console.log("用户登录");
    next(err);
}, function(req, res, next) {
    res.send("用户登录");
    next();

});​

app.use(function(req, res) {
    res.status(404).send("未找到指定页面");

});​
app.listen(8080);
```

#### 内置中间件

从版本4.x开始，Express不再依赖Content，也就是说Express以前的内置中间件作为单独模块，express.static是Express的唯一内置中间件。

express.static(root, [options]); 

通过express.static我们可以指定要加载的静态资源。

#### 第三方中间件

形如之前我们的body-parser，采用引入外部模块的方式来获得更多的应用操作。如后期的cookie和session。

``` js
var express = require('express');
var app = express();
var cookieParser = require('cookie-parser');
```

以上就是关于express中间件类型，在实际项目中，中间件都是必不可少的，因此熟悉使用各种中间件会加快项目的开发效率。



### Cookie的安装及使用

#### 1.安装

```
cnpm install cookie-parser --save
```

#### 2.引入

```
const cookieParser=require("cookie-parser");
```

#### 3.设置中间件

```
app.use(cookieParser());
```

#### 4.设置cookie

```
res.cookie("name",'zhangsan',{maxAge: 900000, httpOnly: true});
//res.cookie(名称,值,{配置信息})
```

关于设置cookie的参数说明：

1. domain: 域名  
2. name=value：键值对，可以设置要保存的 Key/Value，注意这里的 name 不能和其他属性项的名字一样 
3. Expires： 过期时间（秒），在设置的某个时间点后该 Cookie 就会失效，如 expires=Wednesday, 09-Nov-99 23:12:40 GMT。
4. maxAge： 最大失效时间（毫秒），设置在多少后失效 。
5. secure： 当 secure 值为 true 时，cookie 在 HTTP 中是无效，在 HTTPS 中才有效 。
6. Path： 表示 在那个路由下可以访问到cookie。
7. httpOnly：是微软对 COOKIE 做的扩展。如果在 COOKIE 中设置了“httpOnly”属性，则通过程序（JS 脚本、applet 等）将无法读取到COOKIE 信息，防止 XSS 攻击的产生 。
8. singed：表示是否签名cookie, 设为true 会对这个 cookie 签名，这样就需要用 res.signedCookies 而不是 res.cookies 访问它。被篡改的签名 cookie 会被服务器拒绝，并且 cookie 值会重置为它的原始值。

#### 5.获取cookie

```
req.cookies.name;
```

下面是一个基础实例：

```
const express=require("express");
const cookieParser=require("cookie-parser");

var app=express();

//设置中间件
app.use(cookieParser());

app.get("/",function(req,res){
    res.send("首页");
});

//设置cookie
app.get("/set",function(req,res){
    res.cookie("userName",'张三',{maxAge: 20000, httpOnly: true});
    res.send("设置cookie成功");
});

//获取cookie
app.get("/get",function(req,res){
    console.log(req.cookies.userName);
    res.send("获取cookie成功，cookie为："+ req.cookies.userName);
});

app.listen(8080);
```

当访问set路由后会设置cookie，当访问get路由后会获取到设置的cookie值。当然你也可以在其他页面继续获取当前cookie，以实现cookie共享。

### 关于session

session是另一种记录客户状态的机制，与cookie保存在客户端浏览器不同，session保存在服务器当中；
当客户端访问服务器时，服务器会生成一个session对象，对象中保存的是key:value值，同时服务器会将key传回给客户端的cookie当中；当用户第二次访问服务器时，就会把cookie当中的key传回到服务器中，最后服务器会吧value值返回给客户端。
因此上面的key则是全局唯一的标识，客户端和服务端依靠这个全局唯一的标识来访问会话信息数据。

#### 设置session

我们使用express-session模块来设置session

##### 1.安装express-session

```
cnpm install express-session --save
```

##### 2.引入express-session模块

```
const session=require("express-session");
```

##### 3.设置session

```
session(options);
```


如下列代码：

```
const express=require("express");
const session=require("express-session");

var app=express();

//配置中间件
app.use(session({
	secret: "keyboard cat",
	 resave: false,
	 saveUninitialized: true,
	 cookie: ('name', 'value',{maxAge:  5*60*1000,secure: false})
}));

app.use('/login',function(req,res){
	//设置session
	req.session.userinfo='张三';
	res.send("登陆成功！");
});

app.use('/',function(req,res){
	//获取session
	if(req.session.userinfo){
		res.send("hello "+req.session.userinfo+"，welcome");
	}else{
		res.send("未登陆");
	}
});

app.listen(8080);
```

在session(option)中对session进行设置

#### session的常用方法

```
//设置session
req.session.username="张三"

//获取session
req.session.username

//重新设置cookie的过期时间
req.session.cookie.maxAge=1000;

//销毁session
req.session.destroy(function(err){
	
})
```


以下演示通过销毁session的方式来退出登录

```
const express=require("express");
const session=require("express-session");

var app=express();

//配置中间件
app.use(session({
	secret: "keyboard cat",
	 resave: false,
	 saveUninitialized: true,
	 cookie: ('name', 'value',{	maxAge:  5*60*1000,
								secure: false,
								name: "seName",
								resave: false})
}));

app.use('/login',function(req,res){
	//设置session
	req.session.userinfo='张三';
	res.send("登陆成功！");
});

app.use('/loginOut',function(req,res){
	//注销session
	req.session.destroy(function(err){
		res.send("退出登录！"+err);
	});
});

app.use('/',function(req,res){
	//获取session
	if(req.session.userinfo){
		res.send("hello "+req.session.userinfo+"，welcome to index");
	}else{
		res.send("未登陆");
	}
});

app.listen(8080);
```

当我们进入到主页时，未显示任何信息，进入login路由后，自动设置session，这是回到主页则显示session信息，之后进入loginOut路由已注销session信息，再回到首页显示为登陆。

