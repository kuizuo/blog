---
title: vscode插件推荐与快捷键
date: 2021-08-03
tags:
 - vscode
 - 开发工具

---

关于vscode介绍和安装啥的不在这浪费口舌，上号就完事了！

![vscode上号](https://img.kuizuo.cn/vscode%E4%B8%8A%E5%8F%B7.jpg)

<!-- truncate -->

`vscode` 算是我用的最多的一款文本编辑器，也是我用过最好用的文本编辑器，这一年都在和vscode打交道，不得不说一句微软牛逼！

这里我会推荐一些关于vscode的一些相关配置，与常用操作对我来说能提高我一定编写代码的效率。

## 插件推荐

### Bracket Pair Colorizer 2

![image-20210817213845020](https://img.kuizuo.cn/image-20210817213845020.png)

如果你不希望你的代码中白茫茫一片的，或者说想让括号更好看一点，那么这个插件特别推荐。此外，有时候代码写多了，要删除嵌套括号的时候，如果有颜色标识，在寻找的时候必然是轻松的一件事情。

### indent-rainbow

正如插件名，彩虹缩进，能让你的代码中不同长度的缩进呈现不同的颜色（上面的代码缩进有略微的颜色差），有时候在缩进特别多的时候尤其有效，当然，配合VScode快捷键`Ctrl + Shift + \`能快速定位下一个括号所在的位置

### Color Highlight

既然括号可以高亮有颜色，那说到颜色肯定少不了这个插件，有时候遇到 #FF0000 这样的rgb表示颜色，又不想打开查看颜色转化工具，安装这个插件后，就可以将对应的颜色像上面这样直接显示出来。（注意看上图前面的rgb）

### Prettier

首先要知道vscode代码格式化快捷键是Shift + Alt + F，然而vscode自带的代码格式化对于一些文件并没有格式化操作，比如vue，这时候你下载这个插件即可格式化vue代码。

我在用了vscode半年后才知道有这么好用的格式化插件，之前用的是Beautify但是格式化的效果，并不是我满意的，并且同样的有些文件并未能格式化。如果还在用Beautify，果然换Prettier准没错。‘

如果是Vue2用户的话，Vetur是必装一个插件，不仅能格式化代码，还能提供相对于的提示，如果转型为Vue3的话，同样也有插件Volar可供选择。

### Turbo Console Log

这个一定要安利一波，有时候测试js代码并不需要调试那么复杂，只是想输出一下结果是什么，然后就要反复的输入`console.log()`，而这个插件就可以一键帮你得到想要输出的结果。一键 注释 / 启用 / 删除 所有 `console.log`，这也是我最常用的一个插件之一。

所要用到的快捷键:

- ctrl + alt + l 选中变量之后，使用这个快捷键生成 console.log
- alt + shift + c 注释所有 console.log
- alt + shift + u 启用所有 console.log
- alt + shift + d 删除所有 console.log

输出的路径则是根据当前代码所在的文件，行数，作用域，变量输出一遍（前面还带有一个小火箭🚀），如下（输出变量a）

 `console.log('🚀 ~ file: demo.ts ~ line 111 test ~ a', a)`

有点可惜的是该插件不支持自定义快捷键。

### Live Server

安装这个插件后，右下角会出现Go Live的按钮，点击试试，如果你当前根目录正好是有index.html这个文件，那么它将会打开你浏览器开启一个本地服务器，端口默认为5500，并浏览所写的html代码，如果没有则是目录文件管理。同样对文件右键也有Open with Live Server字样

要注意的时，你vscode打开的是一个文件夹，并非一个单文件，不然是没有Go Live按钮的。 这个插件用来打开一些要基于web服务器的才能打开的静态页面的时候异为方便。

### Live Share

注意哈，和上者插件名字大不相同，功能也完全不同，这是用于多人同步的一个插件，只需要登录Github或Microsoft账号，就可以将自己的本地代码实时共享给别人看，同时也能实战显示对方这时候所指的代码位置，还能发送信息，在多人远程协作的时候无疑是一把利器。

### GitLens

VScode使用git，这个插件必安装不可。

官方介绍

> Supercharge the Git capabilities built into Visual Studio Code — Visualize code authorship at a glance via Git blame annotations and code lens, seamlessly navigate and explore Git repositories, gain valuable insights via powerful comparison commands, and so much more
>
> 增强Visual Studio代码中内置的Git功能——通过Git注释和代码镜头，一目了然地查看代码作者身份，无缝导航和探索Git存储库，通过强大的比较命令获得有价值的见解，等等

如果想很明显的显示Git版本流程，那么也可以推荐使用Git Graph这个插件虽说可能不如专门的Git可视化软件好用，或者是想IDEA那种自带的git管理。但如果是vscode的话，这个还是不错的。

![image-20210817220205139](https://img.kuizuo.cn/image-20210817220205139.png)

### REST Client

允许在Vscode中发送http请求的并在Vscode中查看响应，我个人在做协议分析的时候常常用到，有多好用呢，

可以直接将抓包的http请求部分，直接vscode中创建临时文件并复制进去。需要的时候直接保存成.http文件即可永久使用。右键选择`Generator Code Snippet`或快捷键`Ctrl + Alt + C`还能够直接生成不同编程语言发送HTTP的例子。体验效果甚至堪比一些HTTP请求工具（说的就是你PostMan）

![image-20210817221312429](https://img.kuizuo.cn/image-20210817221312429.png)

:::caution 

是点击左上角灰色的Send Request，如果有安装Code Runner的用户，容易直接点成右上角的播放键

:::

### CSS Peek

快速查看 CSS 定位的地方，使用也方便，直接按住Ctrl对准要查看的样式的类名，然后在补一个鼠标左键即可定位。按住Ctrl 同样适用于其他定位，如函数，变量等等。。。

## vscode-icons

修改vscode的文件图标，功能: 好看

## 用过但卸载的插件

关于插件推荐也就告一段落，也是说一些实用，且还在用的，像基本必安装的一些插件就不必说了，不过想说说一些之前用过但是卸载的插件。

### Regex Previewer

说实在话，挺鸡肋的一个软件，如果你恰好用过的话，用久了可能会被的Test Regex… 给折磨到，还要占用一行代码，点击后弹出的一个窗口做过修改，关闭时还询问是否需要保存，对我来说我只是测试一下正则而已，总之，这个插件我选择了卸载。

不过这确实初学者接触JS的正则表达式可以方便许多，如果恰好你正则表达式功底不咋地，其实还是很推荐的。

### Markdown Preview Enhanced

为什么会卸载它，原因是因为Typora太好用了，我基本不会用VScode去编写md文档，因为怎么使用都比如Typora，故卸载该插件。

### Todo Tree

这个插件我花费很多时间，原因是能自定义类似TODO这样的标签，编写代码的时候，需要对一些代码做一些注释，比如这段代码我接下来准备做 那么我就可以写上 `// TODO`  待会要在这些，在比如要修改一些代码，或者是修改一个bug，就可以用 `// FIXME` 与 `// BUG` 然而很多时候，TODO 就足以，完全没必要搞得花里胡哨的，至于这个Todo Tree 方便的点就是在资源管理器中，能方便查看自己所写的一些类似TODO标签一样，然而对我来说，TODO 用的确实少，主要手头有正好有事，对当前代码做一个标记即可，回来的时候自然还记得当时这段代码要干嘛。当时接触vscode还没学Markdown，然后笔记就写在了对应的js代码中，然后就有 NOTE POINT STAR TAG 等等标签，还搞各种颜色图标，想想就有点傻，有这时间多敲几行不香吗？

如果需要TODO这类标记，我更是推荐TODO Highlight这个插件。不过需要小配置一下。注意，TODO后需要添加冒号 也就是`TODO:`才会高亮。然后按F1输入TODO即可列出todo相关列表。

### CodeIf

`CodeIf` 是一个用来给变量命名的网站，你只要输入你想起的中文名，它就会给你提供很多建议的命名，很多时候都会遇到词穷的时候，不过编写代码最主要的不是变量名，而是注释。一个好的注释，再差的变量都能明了。然而代码量写多了，这个搜索变量名也少了，自然就卸载了。实际上还是有CodeIf的网站 [CodeIf](https://unbug.github.io/codelf/#username) 当然国内有可能访问不了，需科学上网。

还有一些用过卸载的插件，实在不记得了

## 快捷键

### 常用快捷键

一些Ctrl + C 和 Ctrl + V等就不做过多解释了，主要说一些有可能不知道，并且还在通过鼠标还完成的一些操作。

- `Shift + Alt + F` 代码格式化（可以说是用的最多的一个了）
- `Shift + Alt + R` 在资源管理器中显示 （右键点文件在选择老累了）
- `Shift + Alt + A` 多行注释
- `Shift +Alt + 向下箭头` 复制当前行到下一行
- `Ctrl + D` 下一个匹配的也被选中
- `Ctrl + F2` 匹配所有当前选中文本
- `Ctrl + Shift + L` 获取将当前所选内容的所有匹配项  方便快捷删改（上一操作的升级版）
- `Ctrl + Alt + 向下箭头` 批量复制光标（向下也同理）
- `Ctrl + ~ ` 打开终端 
- `Ctrl + W` 关闭当前界面编辑器（浏览器关于当前页面同样适用）
- `Ctrl + Shift + [` 和 `Ctrl + Shift + ]`  代码折叠展开
- 全部折叠 `Ctrl+K Ctrl+0`和 展开全部 `Ctrl + K Ctrl + J`

以上基本就是我常用的快捷键了，可以说些快捷键，确实提升了我编写代码的效率。

一些冷门究极好用的(真的很冷门,有很好用,相见恨晚)

`Ctrl + Backspace` 删除前一个单词（特别有用）

`Ctrl + Shift + T` 打开刚刚关闭的页面（手残必备）

Ctrl + T 通过匹配文本,来打开文本 （如果已知什么文件有对应文本,直接用这个快捷键定位贼快）

Ctrl + Alt + 右箭头 快捷将当前文件移动到右边单独标签组 （不用在鼠标点击分页按钮）

Ctrl + Shift + 右箭头  可以逐个选择文本,方便

如果可以 使用Ctrl + Shift + K 删除一行 而不是通过Ctrl +X 剪贴一行

- `Ctrl + P` 跳转指定文件内（特别有用）
- `Ctrl + G ` 跳转指定行号（特别有用）

**`Ctrl + Tab` 切换编辑器 （类比于window `Alt + Tab`）**

### 自定义快捷键

同时vscode也支持开发者自定义快捷键使用。主要就是光标定位功能，有时候编写代码的时候，要经常移动光标到指定位置，这时候就需要右手去移动鼠标或者移动到方向键，反复这样操作，有没有什么办法不移动手的前提下移动光标，肯定有，主要也就两种。

- 专属定制键盘或者是可以设置宏按键的键盘，说一个键盘 HHKB 一个被神化为“程序员梦寐以求的神器”，有兴趣可以去搜一下。
- 自定义快捷键

实际上很多时候都没必要自己设置快捷键，不过是为了满足一些人的需求，就比如我主要就设置了6个快捷键分别是：

- `Shift + Alt + J` 左光标移动
- `Shift + Alt + K` 下光标移动
- `Shift + Alt + L` 右光标移动
- `Shift + Alt + I` 上光标移动
- `Shift + Alt + ;` 光标移动至行尾，相当于End键
- `Shift + Alt + H`  光标移动至行首，相当于Home键

设置的话也比较简单，打开设置，找到键盘快捷方式，然后找到光标移动的快捷键然后，或者是打开对应的keybindings.json文件，把下面代码添加即可。

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
]
```

自定义快捷键也是因人而异，并非每个人都适合，键盘固然方便，但也没有鼠标来的直接。这里也只是提及一下我使用vscode中一些快捷键设置。

此外还设置了一些，例如配置语言特定，通过双击空白创建新文件的时候，默认是纯文本，想要格式为js或者其他的，需要点击右下小角来切换，特别麻烦，于是就给自己设置了一个快捷键

首先在键盘快捷方式找到配置语言特定的设置，

设置为Ctrl + i Ctrl + k   因人而异

## 自写vscode插件

未写，待定…（主要还不会，后续学了在补充）