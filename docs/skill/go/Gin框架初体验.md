---
id: try-gin-framework
slug: /try-gin-framework
title: Gin框架初体验
date: 2021-09-01
authors: kuizuo
tags: [go, gin]
keywords: [go, gin]
---

<!-- truncate -->

## 安装 Gin

[文档 | Gin Web Framework (gin-gonic.com)](https://gin-gonic.com/zh-cn/docs/)

打开命令行窗口，输入

```sh
go get -u github.com/gin-gonic/gin
```

大概率可能安装不上，一般这里就需要配置 Go 代理

## 使用

创建文件夹 GinTest，进入目录输入命令`go mod init GinTest`来管理项目的包

创建文件 main.go 内容为

```go title="main.go"
package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.String(200, "你好,gin")
	})

	r.Run()
}
```

通过`go run "f:\GO\GinTest\main.go"`即可运行 go 服务。

![image-20210831045351327](https://img.kuizuo.cn/image-20210831045351327.png)

通过浏览器访问`http:127.0.0.1:8080`便可输出`你好,gin`

### 热加载

由于每次更改代码后都需要重新启动，通过热加载可以省去每次手动编译的过程

### Fresh

这边使用的是 fresh，还有其他的热加载工具，例如 Air，bee，gin 等等

```sh
go get github.com/pilu/fresh
```

接着输入 fresh 即可

![image-20210831061629685](https://img.kuizuo.cn/image-20210831061629685.png)

同时还会在当前目录下创建 tmp 文件夹，有个编译好的可执行文件。

### 返回数据格式

上面代码所演示的`c.String()` 返回的是文本格式，但有时候要返回的可能是一个 JSON 类型，或者是一个 HTML 或 XML 格式。这时候的话就需要使用其他方法了

### JSON

```go title="main.go"
r.GET("/json", func(c *gin.Context) {
	c.JSON(200, map[string]interface{}{
		"code": 200,
		"msg":  "成功",
	})
})
```

浏览器访问http://127.0.0.1:8080/json显示如下数据

```json
{ "code": 200, "msg": "成功" }
```

> 注: msg 属性后，必须要有,号

其中`map[string]interface{}`可以简写为`gin.H`

也可通过定义结构体

```go title="main.go"
type Article struct {
	Title   string `json:"title"`
	Desc    string `json:"desc"`
	Content string `json:"content"`
}

r.GET("/json3", func(c *gin.Context) {
	a := &Article{
		Title:   "这是标题",
		Desc:    "描述",
		Content: "测试内容",
	}

	c.JSON(200, a)
})
```

得到数据

```json
{ "title": "这是标题", "desc": "描述", "content": "测试内容" }
```

JSONP 与 XML 数据就不做介绍，顺便提一下，这年头还有人用 JSONP 来跨域吗？

### HTML

要发送 HTML 的话，首先在根目录下创建文件夹`templates`，再创建一个文件`test.html`，其中`<body>`内容为

```html title="/templates/test.html"
<body>
  <h2>{{.title}}</h2>
</body>
```

接着在 main.go 中配置 Html 模板文件，如下

```go title="main.go"
r := gin.Default()
r.LoadHTMLFiles("templates/*")
```

重启下服务，然后就可以在路由中返回 HTML 文件，如

```go title="main.go"
r.GET("/html", func(c *gin.Context) {

	c.HTML(200, "test.html", gin.H{
		"title": "一个标题而已",
	})
})
```

结果就不放图了，就是将`一个标题而已`填入至 h2 标签处

### 配置静态 Web 目录

和配置 html 模板一样，先在根目录下创建一个静态 web 目录 static，然后添加

```go title="main.go"
r.Static("/static", "./static")
```

访问http://127.0.0.1:8080/static 就能访问静态文件夹下的资源

### 获取 Query 参数

```go title="main.go"
r.GET("/query", func(c *gin.Context) {
	username := c.Query("username")
	page := c.DefaultQuery("page", "1")

	c.String(200, username+page)
})
```

浏览器请求http://127.0.0.1:8080/query?username=kuizuo 便可输出 `kuizuo1`

### 获取 Post 数据

```go title="main.go"
r.POST("/add", func(c *gin.Context) {
    username := c.PostForm("username")
    password := c.PostForm("password")

    c.String(200, username+password)
})
```

使用 api 请求工具发送 post 数据便可输出相应数据

### Post 传值绑定到结构体

```go title="main.go"
type UserInfo struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

r.POST("/add1", func(c *gin.Context) {
	user := &UserInfo{}

	if err := c.ShouldBind(&user); err == nil {
		c.JSON(200, user)
	} else {
		c.JSON(400,gin.H{
			"err":err.Error()
		})
	}
})
```

同样使用 api 请求工具，发送 post 数据，就可直接通过 user 获取信息

### 动态路由传值

```go title="main.go"
r.GET("/list/:id", func(c *gin.Context) {
    id := c.Param("id")
    c.String(200, id)
})
```

浏览器请求http://127.0.0.1:8080/list/123 id 便可赋值为 123

### 路由分组

在根目录下创建文件夹`routers`，里面创建路由文件，如`apiRouters.go`，内容如下

```go title="/routers/apiRouters.go"
package routers

import "github.com/gin-gonic/gin"

func ApiRoutersInit(r *gin.Engine) {
	apiRouters := r.Group("/api")
	{
		apiRouters.GET("/json", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"code": 200,
				"msg":  "成功",
			})
		})
	}
}
```

接着在`main.go`文件中，导入 routers

```go title="main.go"
import (
	"GinTest/routers"
	"github.com/gin-gonic/gin"
)
```

同时输入

```go title="main.go"
r := gin.Default()

routers.ApiRoutersInit(r)
```

访问http://127.0.0.1:8080/api/json，显示`{"code":200,"msg":"成功"}`

### 控制器

在根目录下创建文件夹`controllers`，里面创建控制器文件，如`userController.go`，内容如下

```go title="/controllers/user/userController.go"
package user

import "github.com/gin-gonic/gin"

type UserController

func UserList(c *gin.Context) {
	c.String(200, "用户列表")
}

func UserAdd(c *gin.Context) {
	c.String(200, "添加用户")
}

func UserEdit(c *gin.Context) {
	c.String(200, "编辑用户")
}
```

```go title="/routers/userRouters.go"
package routers

import (
	"GinTest/controllers/user"
	"github.com/gin-gonic/gin"
)

func UserRoutersInit(r *gin.Engine) {
	userRouters := r.Group("/user")
	{
		userRouters.GET("/list", user.UserList)
		userRouters.GET("/add", user.UserAdd)
		userRouters.GET("/edit", user.UserEdit)
	}
}
```

分别访问对应三个路由，都可得到对应结果

也可以通过控制器结构体优化成如下

```go title="/controllers/user/userController.go"
package user

import "github.com/gin-gonic/gin"

type UserController struct {
}

func (con UserController) List(c *gin.Context) {
	c.String(200, "用户列表")
}

func (con UserController) Add(c *gin.Context) {
	c.String(200, "添加用户")
}

func (con UserController) Edit(c *gin.Context) {
	c.String(200, "编辑用户")
}
```

```go title="/routers/userRouters.go"
package routers

import (
	"GinTest/controllers/user"

	"github.com/gin-gonic/gin"
)

func UserRoutersInit(r *gin.Engine) {
	userRouters := r.Group("/user")
	{
		userRouters.GET("/list", user.UserController{}.List)
		userRouters.GET("/add", user.UserController{}.Add)
		userRouters.GET("/edit", user.UserController{}.Edit)
	}
}
```

### 中间件

中间件本质上就是一个函数，路由执行的时候可以在对应的地方添加中间件执行，如

#### 局部中间件

```go title="main.go"
func initMiddleware(c *gin.Context) {
	fmt.Println("1-中间件")

	c.Next()

	fmt.Println("2-中间件")
}

r.GET("/", initMiddleware, func(c *gin.Context) {
    c.String(200, "你好,gin")
})
```

访问http://127.0.0.1:8080便会输出 `1-中间件` `2-中间件`

#### 全局中间件

```go title="main.go"
r.Use(initMiddleware)
```

这样就需要给每个路由添加中间件配置，所有路由请求后都将会输出。

#### 分组中间件

与全局中间件使用一样，如

```go title="/routers/apiRouters.go"
apiRouters := r.Group("/api",initMiddleware)

// 或
apiRouters := r.Group("/api")
apiRouters.Use(initMiddleware)
```

可以创建中间件目录`middlewares`，创建文件`init.go`，内容

```go title="/middleware/init.go"
package middlewares

import (
	"fmt"
	"github.com/gin-gonic/gin"
)

func InitMiddleware(c *gin.Context) {
	fmt.Println("1-中间件")

	c.Next()

	fmt.Println("2-中间件")
}
```

使用如下（前提需要导入中间件的包）

```go title="/routers/apiRouters.go"
apiRouters.Use(middlewares.InitMiddleware)
```

#### 取消默认中间件

gin.Default()默认使用了 Logger 和 Recovery 中间件

```go
// Default returns an Engine instance with the Logger and Recovery middleware already attached.
func Default() *Engine {
	debugPrintWARNINGDefault()
	engine := New()
	engine.Use(Logger(), Recovery())
	return engine
}
```

如果需要上面两个默认的中间件，可以使用 gin.New()新建一个没有任何中间件的路由

#### 中间件中使用 goroutine 协程

```go title="/middleware/init.go"
func InitMiddleware(c *gin.Context) {
	fmt.Println("1-中间件")

	cCp := c.Copy()
	go func() {
		time.Sleep(2 * time.Second)
        fmt.Println("path: " + cCp.Request.URL.Path)
	}()

	c.Next()

	fmt.Println("2-中间件")
}
```

请求完成两秒后，将会打印`path /`

### 文件上传

```go title="main.go"
r.MaxMultipartMemory = 8 << 20 // 8 MiB
r.POST("/upload", func(c *gin.Context) {
	// 单文件
	file, _ := c.FormFile("file")
	log.Println(file.Filename)

	// 上传文件至指定目录
	dst := path.Join("./static/upload", file.Filename)
	c.SaveUploadedFile(file, dst)

	c.String(200, fmt.Sprintf("'%s' uploaded!", file.Filename))
})
```

使用 curl，即可上传文件

```sh
curl -X POST http://localhost:8080/upload \
  -F "file=@/Users/appleboy/test.zip" \
  -H "Content-Type: multipart/form-data"
```

## 最终项目结构

![image-20210901033059576](https://img.kuizuo.cn/image-20210901033059576.png)

## 整体感受

说实话，我已经快一年没真正接触一门新的语言了，写 Js 和 Ts 代码也写了快一年了，初次体验 Gin 框架整体感受还算不错，大部分的后端框架路由基本都是这么写的，体验过 Express，Flask 路由写法大致相同。

仅仅只是初步体验，后续估计会考虑尝试上手 gin-vue-admin 项目

[自动化全栈后台管理系统 | Gin-Vue-Admin](https://www.gin-vue-admin.com/)
