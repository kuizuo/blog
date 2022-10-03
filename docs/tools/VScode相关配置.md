---
id: vscode-config
slug: /vscode-config
title: VScode相关配置
date: 2021-08-03
authors: kuizuo
tags: [vscode, 开发工具, 配置]
keywords: [vscode, 开发工具, 配置]
---

关于 vscode 介绍和安装啥的不在这浪费口舌，上号就完事了！

![vscode上号](https://img.kuizuo.cn/vscode%E4%B8%8A%E5%8F%B7.jpg)

看一大堆vscode相关推荐，不如直接把别人的vscode配置直接导入到本地上运行测试。
以下是我的 Vscode 全部配置文件，需要的可自行下载导入（替换本地 vscode 相对应的配置文件即可）。

> 下载地址 https://pan.kuizuo.cn/s/RgiP 密码 kuizuo

<!-- truncate -->

## 前言

`vscode` 算是我用的最多的一款文本编辑器，也是我用过最好用的文本编辑器，这一年都在和 vscode 打交道，不得不说一句微软牛逼！

这里我会推荐一些关于 vscode 的一些相关配置，与常用操作对我来说能提高我一定编写代码的效率（常用不写）。

## 插件推荐

### GitHub Copilot

AI 写代码，用过都说好。

官网地址 [GitHub Copilot · Your AI pair programmer](https://copilot.github.com/)

### Bracket Pair Colorizer 2

![image-20210817213845020](https://img.kuizuo.cn/image-20210817213845020.png)

如果你不希望你的代码中白茫茫一片的，或者说想让括号更好看一点，那么这个插件特别推荐。此外，有时候代码写多了，要删除嵌套括号的时候，如果有颜色标识，在寻找的时候必然是轻松的一件事情。

现 Vscode 自带该功能，无需安装插件，在设置中搜索 Bracket Pair Colorization，勾选即可。

![image-20220610012923130](https://img.kuizuo.cn/image-20220610012923130.png)

### indent-rainbow

正如插件名，彩虹缩进，能让你的代码中不同长度的缩进呈现不同的颜色（上面的代码缩进有略微的颜色差），有时候在缩进特别多的时候尤其有效，当然，配合 VScode 快捷键`Ctrl + Shift + \`能快速定位下一个括号所在的位置

### Prettier

首先要知道 vscode 代码格式化快捷键是 Shift + Alt + F，然而 vscode 自带的代码格式化对于一些文件并没有格式化操作，比如 vue，这时候你下载这个插件即可格式化 vue 代码。

我在用了 vscode 半年后才知道有这么好用的格式化插件，之前用的是 Beautify 但是格式化的效果，并不是我满意的，并且同样的有些文件并未能格式化。如果还在用 Beautify，果然换 Prettier 准没错。

如果是 Vue2 用户的话，Vetur 是必装一个插件，不仅能格式化代码，还能提供相对于的提示，如果转型为 Vue3 的话，同样也有插件 Volar 可供选择。

### ESLint

前端工程化代码规范必备，无需多言。

### Turbo Console Log

这个一定要安利一波，有时候测试 js 代码并不需要调试那么复杂，只是想输出一下结果是什么，然后就要反复的输入`console.log()`，而这个插件就可以一键帮你得到想要输出的结果。一键 注释 / 启用 / 删除 所有 `console.log`，这也是我最常用的一个插件之一。

所要用到的快捷键:

- ctrl + alt + l 选中变量之后，使用这个快捷键生成 console.log
- alt + shift + c 注释所有 console.log
- alt + shift + u 启用所有 console.log
- alt + shift + d 删除所有 console.log

输出的路径则是根据当前代码所在的文件，行数，作用域，变量输出一遍（前面还带有一个小火箭 🚀），如下（输出变量 a）

`console.log('🚀 ~ file: demo.ts ~ line 111 test ~ a', a)`

有点可惜的是该插件不支持自定义快捷键。

### Live Server

安装这个插件后，右下角会出现 Go Live 的按钮，点击试试，如果你当前根目录正好是有 index.html 这个文件，那么它将会打开你浏览器开启一个本地服务器，端口默认为 5500，并浏览所写的 html 代码，如果没有则是目录文件管理。同样对文件右键也有 Open with Live Server 字样

要注意的时，你 vscode 打开的是一个文件夹，并非一个单文件，不然是没有 Go Live 按钮的。 这个插件用来打开一些要基于 web 服务器的才能打开的静态页面的时候异为方便。

### Live Share

注意哈，和上者插件名字大不相同，功能也完全不同，这是用于多人同步的一个插件，只需要登录 Github 或 Microsoft 账号，就可以将自己的本地代码实时共享给别人看，同时也能实战显示对方这时候所指的代码位置，还能发送信息，在多人远程协作的时候无疑是一把利器。

### REST Client

允许在 Vscode 中发送 http 请求的并在 Vscode 中查看响应，我个人在做协议分析的时候常常用到，有多好用呢，

可以直接将抓包的 http 请求部分，直接 vscode 中创建临时文件并复制进去。需要的时候直接保存成.http 文件即可永久使用。右键选择`Generator Code Snippet`或快捷键`Ctrl + Alt + C`还能够直接生成不同编程语言发送 HTTP 的例子。体验效果甚至堪比一些 HTTP 请求工具（说的就是你 PostMan）

![image-20210817221312429](https://img.kuizuo.cn/image-20210817221312429.png)

:::caution

是点击左上角灰色的 Send Request，如果有安装 Code Runner 的用户，容易直接点成右上角的播放键

:::

### Thunder Client

![image-20221003223247386](https://img.kuizuo.cn/image-20221003223247386.png)

要想在 Vscode 拥有 Postman 或者 ApiPost 的接口调试工具，不妨使用这个插件，支持分类，环境变量，如果仅作为个人测试，不要求接口分享，这个插件就足以满足大部分日常 api 接口调试。

### CSS Peek

快速查看 CSS 定位的地方，使用也方便，直接按住 Ctrl 对准要查看的样式的类名，然后在补一个鼠标左键即可定位。按住 Ctrl 同样适用于其他定位，如函数，变量等等。。。

### Project Manager

![image-20220610013640476](https://img.kuizuo.cn/image-20220610013640476.png)

对于一些常用项目而言，可以通过该插件添加到 Vscode 中，直接在左侧项目管理器中便可直接使用 vscode 打开项目工程。

还有挺多使用插件没介绍到，个人建议还是直接下载对应的配置文件，将其导入即可，配置文件包含插件、主题、快捷键，布局等等。

## 快捷键

### 常用快捷键

一些 Ctrl + C 和 Ctrl + V 等就不做过多解释了，主要说一些有可能不知道，并且还在通过鼠标还完成的一些操作。

- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>F</kbd> 代码格式化
- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>R</kbd> 在资源管理器中显示 （右键点文件在选择老累了）
- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>A</kbd> 多行注释
- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>向下箭头</kbd> 复制当前行到下一行
- <kbd>Ctrl</kbd>+<kbd>D</kbd> 下一个匹配的也被选中
- <kbd>Ctrl</kbd>+<kbd>F2</kbd> 匹配所有当前选中文本
- <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>L</kbd> 获取将当前所选内容的所有匹配项 方便快捷删改（上一操作的升级版）
- <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>向下箭头</kbd> 批量复制光标（向下也同理）
- <kbd>Ctrl</kbd>+<kbd>~</kbd> 打开终端
- <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>[</kbd> 代码折叠
- <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>]</kbd> 代码展开
- <kbd>Ctrl</kbd>+<kbd>K</kbd> <kbd>Ctrl</kbd>+<kbd>0</kbd> 全部折叠
- <kbd>Ctrl</kbd>+<kbd>K</kbd> <kbd>Ctrl</kbd>+<kbd>J</kbd> 展开全部

- <kbd>Ctrl</kbd>+<kbd>Backspace</kbd> 删除前一个单词（特别有用）

- <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>右箭头</kbd> 快捷将当前文件移动到右边单独标签组 （不用在鼠标点击分页按钮）

- <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>右箭头</kbd> 可以逐个选择文本,方便

- 如果可以 使用 Ctrl + Shift + K 删除一行 而不是通过 Ctrl +X 剪贴一行

以下功能，能用快捷键就别用鼠标了

- **<kbd>Ctrl</kbd>+<kbd>E</kbd>/<kbd>P</kbd> 跳转到近期文件(再次按下即可切换下一个文件,加 <kbd>Shift</kbd>则是上一个文件)**
- **<kbd>Ctrl</kbd>+<kbd>Tab</kbd> 切换Tab （类比于 window <kbd>Alt</kbd>+<kbd>Tab</kbd>）在已显示的 Tab 切换比上面好用一些**
- <kbd>Ctrl</kbd>+<kbd>G</kbd> 跳转到某行(别再滚动鼠标了)
- <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>O</kbd> 跳转(列举)当前文件某个函数
- **<kbd>Ctrl</kbd>+<kbd>T</kbd> 全局搜索某个函数(markdown则是标题)**
- <kbd>Ctrl</kbd>+<kbd>N</kbd> 创建一个临时文件(别再鼠标双击tab栏了)
- <kbd>**Ctrl</kbd>+<kbd>W</kbd> 关闭当前Tab页面（浏览器适用，别加Shift，别再鼠标点击关闭按钮了）**
- **<kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>T</kbd> 打开刚刚关闭的页面（手残必备,浏览器适用）**
- <kbd>Ctrl</kbd>+<kbd>B</kbd> 切换左侧导航栏

以上基本就是我常用的快捷键了，可以说些快捷键，确实提升了我编写代码的效率。这里强烈建议马上打开Vscode，在不借用鼠标的情况下，使用以上快捷键。会有意想不到的使用体验！

### 自定义快捷键

同时 vscode 也支持开发者自定义快捷键使用。主要就是光标定位功能，有时候编写代码的时候，要经常移动光标到指定位置，这时候就需要右手去移动鼠标或者移动到方向键，反复这样操作，有没有什么办法不移动手的前提下移动光标，肯定有，主要也就两种。

- 专属定制键盘或者是可以设置宏按键的键盘，说一个键盘 HHKB 一个被神化为“程序员梦寐以求的神器”，有兴趣可以去搜一下。
- 自定义快捷键

实际上很多时候都没必要自己设置快捷键，不过是为了满足一些人的需求，就比如我主要就设置了 6 个快捷键分别是：

- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>J</kbd> 左光标移动
- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>K</kbd> 下光标移动
- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>L</kbd> 右光标移动
- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>I</kbd> 上光标移动
- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>;</kbd> 光标移动至行尾，相当于 End 键
- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>H</kbd> 光标移动至行首，相当于 Home 键
- <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>U</kbd> 选中代码片段，即可合并成一行代码。

设置的话也比较简单，打开设置，找到键盘快捷方式，然后找到光标移动的快捷键然后，或者是打开对应的 keybindings.json 文件，把下面代码添加即可。

```json
[
  {
    "key": "shift+alt+j",
    "command": "cursorLeft",
    "when": "textInputFocus"
  },
  {
    "key": "shift+alt+l",
    "command": "cursorRight",
    "when": "textInputFocus"
  },
  {
    "key": "shift+alt+i",
    "command": "cursorUp",
    "when": "textInputFocus"
  },
  {
    "key": "shift+alt+k",
    "command": "cursorDown",
    "when": "textInputFocus"
  },
  {
    "key": "shift+alt+h",
    "command": "cursorHome",
    "when": "textInputFocus"
  },
  {
    "key": "shift+alt+oem_1",
    "command": "cursorEnd",
    "when": "textInputFocus"
  },
  {
    "key": "shift+alt+u",
    "command": "editor.action.joinLines"
  }
]
```

自定义快捷键也是因人而异，并非每个人都适合，键盘固然方便，但也没有鼠标来的直接。这里也只是提及一下我使用 vscode 中一些快捷键设置。

此外还设置了一些，例如配置语言特定，通过双击空白创建新文件的时候，默认是纯文本，想要格式为 js 或者其他的，需要点击右下小角来切换，特别麻烦，于是就给自己设置了一个快捷键

首先在键盘快捷方式找到配置语言特定的设置，

设置为 Ctrl + i Ctrl + k 因人而异

## 代码提示

相信你在使用`vscode`中，肯定有过这样的问题，明明引入本地模块，但是有的时候就是没有对应的代码提示。如图

![image-20200901212906150](https://img.kuizuo.cn/image-20200901212906150.png)

像导入本地模块`fs`，却没有代码提示，想要有本地模块代码提示，最快捷的方法就是通过下面一行代码

```shell
npm install @types/node
```

但是如果你像上面那样，目录下没有`package.json`文件是肯定安装不上去的，这时候是需要初始化项目结构也就是执行下面的代码

```shell
npm init
或
npm init -y
```

然后在目录下你就能看到`node_modules`，在这个文件夹下有一个`@types`，这个目录就是存放你以后代码提示的目录，现在`@types`里面有`node`这个文件夹，也就是我们刚刚这个命令`npm install @types/node`后的 node，现在试试看确实是有代码提示了，并且还有带星推荐。

![image-20200901214223439](https://img.kuizuo.cn/image-20200901214223439.png)

现在，我的代码里有`jquery`代码，但是本地已有`jquery.js`文件，又不想安装`jquery`的模块，但是又要`jquery`的代码提示，这时候你就可以输入下面代码，就能看到对应的代码。

```shell
npm install @types/jquery
```

![image-20200901214906038](https://img.kuizuo.cn/image-20200901214906038.png)

在比如有的库安装会没带代码提示，这时候就用上面的方法同样也可以有代码提示，例如`express`

`express`相关安装操作我就不赘述了，先看图片

![image-20200901215612611](https://img.kuizuo.cn/image-20200901215612611.png)

这 app 代码提示怎么全是 js 自带的代码提示。

然后在看`node_modules\@types`下，怎么只有我刚刚安装的那几个？

![image-20200901215826419](https://img.kuizuo.cn/image-20200901215826419.png)

不妨试试

```shell
npm install @types/express
```

这时候`node_modules\@types`下，就多了几个文件夹，其中一个名为 express，那么现在代码提示肯定有了。

![image-20200901220225659](https://img.kuizuo.cn/image-20200901220225659.png)

果不其然，`vscode`里也有正常的代码提示了

![image-20200901220329481](https://img.kuizuo.cn/image-20200901220329481.png)

:::info

要注意的是，如果导入的库所采用的是 TypeScript 所书写的，那么就无需引用@types/xxx。而一些远古的库所采用的 JavaScript 编写的，所以自然没有代码提示，就需要借用 typescript 官方提供的@types/xxx 包。

:::

从上面的例子中，可以得出`@types`这个文件夹里存放的都是`vscode`当前工作区的代码提示文件，想要对应的代码提示就直接`npm i @types/模块名`即可，如果你当前工作区没有代码提示，那么多半是这个问题。

### 自定义代码提示与快捷输入

这里补充一下，有时候我想自己定义一个代码提示，有没有办法呢，当然有，如果你恰巧学过 java，想必每次写`System.out.println`都痛苦的要死，这时候你就可以像这样

1. 创建一个.vscode 文件夹，在文件夹里创建一个名为`kuizuo.code-snippets`（只要后缀是 code-snippets 就行）
2. 在这个文件内写上如下代码

```json
{
  "System.out.println": {
    "scope": "java",
    "prefix": "syso",
    "body": ["System.out.println($1);"],
    "description": "输出至控制台，并带上换行符"
  }
}
```

- System.out.println 为代码块的名字，无需强制。
- prefix：触发代码片段
- body：按下 TAB 后触发的内容填充，注意是一个数组类型，每行都需要用双引号修饰，不能使用模板字符串
- description：代码提示内容
- scope: 作用的语言，可多选，如"javascript,c"
- $+数字: 为光标的定位符，有多个则 Tab 跳转下个光标位置

上则代码的意思就是输入 prefix 内的`syso` 然后按下 tab 键就会把 body 内的`System.out.println($1);`代码提示显示出来，其中`$1`为光标位置，如图

![](https://img.kuizuo.cn/syso.gif)

但一般很少用到代码块，很多现成的插件就可以完全满足对应代码补全的需求，但有时候会方便很多。

像一些插件内会自带的代码提示，能不能“偷”过来使用一下呢，答案是肯定能的，这里我就已 autoj -pro 为例，(没了解过该软件可以忽视）

1. 首先安装 autoJS_pro 插件，然后进入 C:\Users\Administrato\\.vscode\extensions\hyb1996.auto-js-pro-ext.... （Administrator 为用户名）
2. 找到以 snippets 结尾的文件，打开全选复制其中的代码。
3. 打开 vscode，如上操作，创建一个.vscode 文件夹，后同
4. 把复制的代码段粘贴到我们创建的 snippets 文件，卸载 auto.js-pro 插件，重启即可
