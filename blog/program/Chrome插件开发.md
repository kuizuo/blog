---
slug: chrome-plugin-development
title: Chrome插件开发
date: 2020-09-28
authors: kuizuo
tags: [chrome, plugin, develop]
keywords: [chrome, plugin, develop]
---

<!-- truncate -->

## 前言

相关文章 [谷歌官方文档](https://developer.chrome.com/extensions/manifest) (需翻墙)

[Chrome 插件开发全攻略](http://blog.haoji.me/chrome-plugin-develop.html) （强烈推荐看这一篇！）

你只需要看完上面那篇文章和掌握一些前端开发基础，就足以自行编写一个 Chrome 插件。本文也是基于上面文章加上自己之前写的插件所记。

### 什么是 Chrome 插件

如果你用过 Chrome 浏览器的话，也许会用到过一些插件，其中比较知名的就是油猴插件，通过这些插件能够帮你例如自动完成一些功能，屏蔽广告，相当于一个浏览器内置的脚本。应该来说这是 Chrome 扩展开发，不过说 Chrome 插件更顺口，后文也会说成 Chrome 插件。

### 安装 Chrome 插件

首先打开 Chrome，如下图即可进入插件的管理页面

![image-20200922225606159](https://img.kuizuo.cn/image-20200922225606159.png)

这时候记得把右上角的开发者模式给勾上，如果不勾上的话你无法直接将文件夹拖入 Chrome 进行安装，就只能安装`.crx`格式的文件。Chrome 要求插件必须从它的 Chrome 应用商店（需要翻墙）安装，其它任何网站下载的都无法直接安装，所以可以把`crx`文件解压，然后通过开发者模式直接加载。

然后将写好的 Chrome 插件文件夹拖入到刚刚打开的插件管理页面即可。

## Chrome 插件知识

### manifest.json

是`manifest.json`切记不要英文单词打错字，一定要有这个文件，且需要放在根目录上，否则就会出现未能成功加载扩展程序的错误。

### background.html 和 background.js

可以理解为后台，同时这个页面会一直常驻在浏览器中，而主要 background 权限非常高，几乎可以调用所有的 Chrome 扩展 API（除了 devtools），基本很多操作都是放在 background 执行，返回给 content，而且它可以**无限制跨域**，也就是可以跨域访问任何网站而无需要求对方设置`CORS`。这对我们后面要在 content 中发送跨域请求至关重要！

我习惯的做法是通过`”page”："background.html"`来导入`background.js`或其他 js 代码，如下

```json
// manifest.json
 "background": {
    "page": "background.html",
  },
```

```html
<!-- background.html -->
<!DOCTYPE html>
<html>
  <head>
    <title>背景页</title>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  </head>
  <body>
    <script type="text/javascript" src="js/jquery.js"></script>
    <script type="text/javascript" src="js/background.js"></script>
  </body>
</html>
```

如果是 scripts 方式导入 js 文件则需要反复修改`manifest.json`文件。

#### 关于乱码

有时候你在编写代码中出现了中文可能会出现了如下的乱码，

![image-20200923214834081](https://img.kuizuo.cn/image-20200923214834081.png)

我遇到的原因是就是我原先的`background.html`代码写成如下的情况

```html
<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript" src="js/background.js"></script>
```

没错，就只写了这两个行，就出现乱码（将 UTF-8 的编码变为了 windows1252），而只需要把 background.html 代码修改成正常的 HTML 结构，也就是上上面的那个代码即可解决该乱码情况。

### content.js

我们主要的向页面注入脚本就依靠这个文件，相当于给页面添加了一个 js 文件，但是`content`和原始页面**共享 DOM**，但是不共享 JS，如要**访问页面 JS（例如某个 JS 变量）**，只能通过`injected js`来实现（后文会提到）。并且`content`不能访问绝大部分`chrome.xxx.api`，除了下面这 4 种：

- chrome.extension(getURL , inIncognitoContext , lastError , onRequest , sendRequest)
- chrome.i18n
- chrome.runtime(connect , getManifest , getURL , id , onConnect , onMessage , sendMessage)
- chrome.storage

这些 API 绝大部分时候都够用了，非要调用其它 API 的话，你还可以通过通信来实现让 background 来帮你调用。

### inject.js

上文也说到了`content`是**无法访问页面中的 JS**，可以操作 DOM，但是 DOM 却不能调用它，也就是无法在 DOM 中通过绑定事件的方式调用`content`中的代码（包括直接写`onclick`和`addEventListener`2 种方式都不行），但是，**在页面上添加一个按钮并调用插件的扩展 API**是一个很常见的需求，那该怎么办呢？这时候就需要注入 inject.js 这个文件

```js
document.addEventListener('DOMContentLoaded', function () {
  injectCustomJs()
})

// 向页面注入JS
function injectCustomJs(jsPath) {
  jsPath = jsPath || 'js/inject.js'
  var temp = document.createElement('script')
  temp.setAttribute('type', 'text/javascript')
  // 获得的地址类似：chrome-extension://ihcokhadfjfchaeagdoclpnjdiokfakg/js/inject.js
  temp.src = chrome.extension.getURL(jsPath)
  temp.onload = function () {
    // 放在页面不好看，执行完后移除掉
    this.parentNode.removeChild(this)
  }
  document.head.appendChild(temp)
}
```

还没有完，因为注入有权限，所以需要在 manifest.json 声明一下这个文件。也就是下面的这行代码

```js
{
	// 普通页面能够直接访问的插件资源列表，如果不设置是无法直接访问的
	"web_accessible_resources": ["js/inject.js"],
}
```

这样你就能调用

### 关于消息通信

Chrome 插件主要就 4 个部分组成，injected，content，popup，background，但这 4 个部分所对应的权限，应用都有可能各自不一，这时候就需要通过消息通信，将对应的数据发送到对应的文件，主要也就如下四种通信方式：

#### popup 和 background

popup 可以直接调用 background 中的 JS 方法，也可以直接访问 background 的 DOM：

```javascript
// background.js
function test() {
  alert('我是background！')
}

// popup.js
var bg = chrome.extension.getBackgroundPage()
bg.test() // 访问bg的函数
alert(bg.document.body.innerHTML) // 访问bg的DOM
```

`background`访问`popup`如下（前提是`popup`已经打开）：

```javascript
var views = chrome.extension.getViews({ type: 'popup' })
if (views.length > 0) {
  console.log(views[0].location.href)
}
```

#### popup 或 bg 与 content

##### popup 或 bg 向 content 发送请求

```js
//background.js或popup.js：
function sendMessageToContentScript(message, callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    chrome.tabs.sendMessage(tabs[0].id, message, function (response) {
      if (callback) callback(response)
    })
  })
}

sendMessageToContentScript({ cmd: 'test', value: '你好，我是popup！' }, function (response) {
  console.log('来自content的回复：' + response)
})
```

`content.js`通过监听事件接收：

```js
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  // console.log(sender.tab ?"from a content script:" + sender.tab.url :"from the extension");
  if (request.cmd == 'test') alert(request.value)
  sendResponse('我收到了你的消息！')
})
```

##### content 向 popup 或 bg

```js
// content.js
chrome.runtime.sendMessage({ greeting: '你好，我是content呀，我主动发消息给后台！' }, function (response) {
  console.log('收到来自后台的回复：' + response)
})
```

```js
//background.js 或 popup.js：
// 监听来自content的消息
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  console.log('收到来自content的消息：')
  console.log(request, sender, sendResponse)
  sendResponse('我是后台，我已收到你的消息：' + JSON.stringify(request))
})
```

注意：

- content_scripts 向`popup`主动发消息的前提是 popup 必须打开！否则需要利用 background 作中转；
- 如果 background 和 popup 同时监听，那么它们都可以同时收到消息，但是只有一个可以 sendResponse，一个先发送了，那么另外一个再发送就无效；

#### injected 和 content

主要就是`injected`向`content`发送，`injected`无需监听。

`content`和页面内的脚本（`injected`自然也属于页面内的脚本）之间唯一共享的东西就是页面的 DOM 元素，有 2 种方法可以实现二者通讯，：

1. 可以通过`window.postMessage`和`window.addEventListener`来实现二者消息通讯；（推荐）
2. 通过自定义 DOM 事件来实现（我就懒得写了，没怎么用到）；

`injected`中：

```js
window.postMessage({ test: '你好！' }, '*')
```

`content script中`：

```js
window.addEventListener(
  'message',
  function (e) {
    console.log(e.data)
  },
  false,
)
```

#### injected 与 popup

`injected`无法直接和`popup`通信，必须借助`content`作为中间人。不过一般这种都少，直接和 bg 通信即可。

## 我的模板

关于 Chrome 的主要内容也就这些，实际开发如果有个模板就能大大方便开发，在原文章中该作者已经分享了有对应的源代码，这里放上我自写的 Chrome 模板编写过程。

![image-20210820004414785](https://img.kuizuo.cn/image-20210820004414785.png)

当然，这里需要提几点地方：

### 配置项与 storage

首先是配置方面，有时候插件的内的选项是要记录，以便下一次在启动插件的时候还是上一次的配置。先看代码

```html
<!-- popup.js -->
<div class="config-item">
  <input type="checkbox" id="config1" class="box configs" />
  <label class="hand" for="config1" title="配置1">配置1</label>
</div>
<div class="config-item">
  <input type="checkbox" id="config2" class="box configs" />
  <label class="hand" for="config2" title="配置2">配置2</label>
</div>
```

```js
// popup.js
$(function () {
  let configs = document.getElementsByClassName('configs')
  for (let i = 0; i < configs.length; i++) {
    let type = configs[i].type
    if (type == 'checkbox') {
      configs[i].onchange = function () {
        chrome.storage.sync.set({
          [this.id]: this.checked,
        })
      }
      chrome.storage.sync.get(configs[i].id, function (items) {
        configs[i].checked = items[configs[i].id] || false
      })
    } else if (type == 'text' || type == 'password') {
      configs[i].onblur = function () {
        chrome.storage.sync.set({ [this.id]: this.value })
      }
      chrome.storage.sync.get(configs[i].id, function (items) {
        configs[i].value = items[configs[i].id] || ''
      })
    }
  }
})
```

可能需要多花点时间才能理解上面代码的意思，首先我在需要记录配置的地方添加了一个类`configs`，然后通过 js 代码遍历类名为`configs`，接着判断是多选框，还是输入框，input 的 id 为键名，value 为键值，来 set 或 get `chrome.storage`的值，然后进行事件绑定为修改配置后在记录一下配置。这里需要注意一下，写配置的时候`{ [this.id]: this.value }`这里的`this.id`是加了中括号的，原因就是这个 this.id 是变量，如果不加的话默认为字符串，但在这里有.所以是会报错的。

强烈不建议用 localStorage，我当初第一遍学的时候没学明白，我还通过消息通信将配置信息发给`content`，然后还用 localStorage 记录一遍，现在才发现`chrome.storage`是针对插件全局的，即使你在`background`或者`popup中`保存的数据，在`content`也能获取到。

当然这种读写配置的也算麻烦了，不像桌面级开发的读写配置。

### 悬浮窗

首先，一般对于网页端的插件，能提供的页面最好方式就是悬浮窗了，这里我也是通过 DOM 创建元素生成对象。而这个悬浮窗是针对页面的，而不是像 popup 那样。相关的页面初始化代码如下，

```js
var view = {
  show: true,
  cache: {
    count: 0,
    type: 0,
    mouse_x: -1,
    mouse_y: -1,
  },
}

function initView() {
  view.float = $(`
	<div id="box"
style="position: fixed;border: 1px double rgb(0,0,0); width: 300px; top: 30px; right: 1%; z-index: 999999; font-size: 15px; background-color: rgb(255,255,255); color: #000000;user-select:none;">
<div style="position: relative;">
	<button name="show"
		style="position: absolute;top: 50%;right:1%; margin-top: 7px; line-height: 18px;overflow:hidden;border: 0px double rgb(0,0,0);cursor:pointer;font-size: 18px;background-color: rgb(255,255,255);">－
	</button>
</div>
<div id="kz_title" style="height: auto; margin: 5px; font-size: 16px;">日志</div>

<div id="kz_main">
	<hr>
	<form>
		<div style="margin-top: 5px;overflow-y: auto;">
			<button id="kz_id1" name="cleanlog"
				style="margin-left: 10px;float:left;border-radius:0em;overflow:hidden;border: 1px double rgb(0,0,0);background-color: rgb(255,255,255);">功能按钮</button>
			<button id="kz_id2" name="cleanlog"
				style="margin-left: 10px;float:left;border-radius:0em;overflow:hidden;border: 1px double rgb(0,0,0);background-color: rgb(255,255,255);">功能按钮</button>
		</div>
	</form><br>
	<div id="logList"></div>
</div>
</div>
	`)
  view.info = view.float.find('#info')
  view.kz_title = view.float.find('#kz_title')
  view.kz_main = view.float.find('#kz_main')
  view.float.appendTo('body').delegate('button', 'click', function (e) {
    e.stopImmediatePropagation()
    e.stopPropagation()
    e.preventDefault()
    let name = $(this).attr('name')
    if (name == 'show') {
      $(this).html(view.show ? '＋' : '－')
      view.show = !view.show
      view.kz_main.slideToggle()
    }
  })
  addViewMouseListener()
  log('日志输出1')
  log('日志输出2')
  log('日志输出3')
}

function addViewMouseListener() {
  view.float.bind('mousedown', function (event) {
    view.cache.x = $(this).position().left
    view.cache.y = $(this).position().top
    view.cache.mouse_x = event.originalEvent.clientX
    view.cache.mouse_y = event.originalEvent.clientY
    //console.log(view.cache.mouse_x, view.cache.mouse_y, view.cache.x, view.cache.y)
  })
  $(document).bind('mousemove', function (event) {
    //计算出现在的位置是多少
    if (view.cache.mouse_x == -1) return
    if (view.cache.mouse_y - view.cache.y > view.kz_title.height()) return
    let new_position_left = event.originalEvent.clientX - view.cache.mouse_x + view.cache.x,
      new_position_top = event.originalEvent.clientY - view.cache.mouse_y + view.cache.y
    //加上边界限制
    if (new_position_top < 0) {
      //当上边的偏移量小于0的时候，就是上边的临界点，就让新的位置为0
      new_position_top = 0
    }
    //如果向下的偏移量大于文档对象的高度减去自身的高度，就让它等于这个高度
    if (new_position_top > $(document).height() - view.float.height() && $(document).height() - view.float.height() > 0) {
      new_position_top = $(document).height() - view.float.height()
    }
    //右限制
    if (new_position_left > $(document).width() - view.float.width()) {
      new_position_left = $(document).width() - view.float.width()
    }
    if (new_position_left < 0) {
      //左边的偏移量小于0的时候设置 左边的位置为0
      new_position_left = 0
    }
    view.float.css({
      left: new_position_left + 'px',
      top: new_position_top + 'px',
    })
  })
  $(document).bind('mouseup', function (event) {
    view.cache.mouse_x = -1
    view.cache.mouse_y = -1
  })
}

function log(msg, color) {
  let date = new Date()
  let t = date.getHours() + ':' + date.getMinutes() + ':' + date.getSeconds()
  msg = t + '  ' + msg
  let div = $('<div class="log"></div>').css({ 'border-color': 'rgba(121, 187, 255, 0.2)', 'background-color': 'rgba(121, 187, 255, 0.2)' })
  let log = $('<p><span style="color: ' + (color || '#409EFF') + '">' + msg + '</span></p>')

  if ($('.log').length > 15) {
    for (let i = 0; $('.log').length - 15; i++) {
      $('.log')[i].remove()
    }
  }
  $('#logList').append(div.append(log))
}
```

然后在 content.js 内容的对页面 url 判断是否需要初始化悬浮窗即可

```js
document.addEventListener('DOMContentLoaded', function () {
  if (location.host.indexOf('chaoxing') != -1) {
    initView()
  }
})
```

如何发挥就看各位了。

### 跨域请求

关于跨域请求，我当初在学习 Chrome 插件的时候，就是卡在了跨域这个地方，那时候前端学的浅，对跨域都不知道处理，然后放弃学习了 Chrome 插件一段时间，后来有时间了，想在补一补之前没写完的 Chrome 扩展搞完。然而跨域请求非常简单，而我那时候之所以卡住就是因为没好好看文档，搞不定的地方就多看几遍说不准就搞定了。

首先要使 Chrome 插件访问跨域资源，需要在 manifest.json 文件中声明要访问的域如下：

```json
{
  "permissions": ["http://www.google.com/", "http://*.google.com/", "https://*.google.com/", "http://*/"]
}
```

建议直接直接暴力点写上

```json
{
  "permissions": ["http://*/*", "https://*/*"]
}
```

然后封装一下对应的 ajax 请求，因为在 content 内进行 ajax 请求，是会在控制台输出跨域请求拦截，或者是 HTTPS 访问 HTTP 不安全等问题，这时候就需要通过消息通信，将 content 要发送的请求发送给 bg，让 bg 请求，然后等 bg 请求完毕，再将数据返回到 content 即可。下面是我对应的封装代码

```js
// background.js
chrome.runtime.onMessage.addListener(function (req, sender, sendResponse) {
  console.log(req, sender, sendResponse)
  if (req.cmd == 'ajax') {
    $.ajax({
      url: req.url,
      type: req.type,
      data: req.data,
      async: false,
      success: function (res) {
        sendResponse(res)
      },
    })
  }
})
```

```js
// content.js
function sendAjaxToBg(url, type, data, callback) {
  chrome.runtime.sendMessage({ cmd: 'ajax', url: url, type: type, data: data }, function (response) {
    callback(response)
  })
}
```

这里的话我通信发送的是 js 对象，其中 cmd 决定了我要的操作，后台通过判断 cmd 来执行对应的操作。比较不好理解的是回调函数，由于 JS 自身语言的因素与浏览器的问题，很多事件都是先挂着，后做完在回调，所以我这里就封装成这种形式，例如

```js
sendAjaxToBg("http://...", "GET", null, function(response){
	console.log(response)
	...code
})
```

这只是一个简单的 http 封装发送，如果要更复杂的话还可以添加协议头和 cookies，这里就不在补充了。

### 一些自写 Chrome 插件

实际上已经写过一些 Chrome 插件了，奈何写的比较烂或没搞完，也就暂时先不发，有时间会再整理一下自己所写的。

一个验证码识别，有时候在登录的时候需要输入验证码是件非常痛苦的事情。于是乎我就通过调用打码 Api 接口写了个自动识别验证码并填写的。也提供了非常方便的右键识别验证码的功能。具体效果如图（实际上还是得第一次先确认要识别的图片框与输入框，下次加载的时候需要手动点击验证码才会自动生效，还是不够智能的，不过成就感十足）

![image-20210820001938051](https://img.kuizuo.cn/image-20210820001938051.png)

![wydm](https://img.kuizuo.cn/wydm.gif)

另一个是基于某布大佬的 WebHook 工具，所更改的，不过一直停滞着，有空将其完善一下。
