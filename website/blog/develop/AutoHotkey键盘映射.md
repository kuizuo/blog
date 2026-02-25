---
slug: autohotkey
title: AutoHotkey键盘映射
date: 2022-07-08
authors: kuizuo
tags: [工具, keyMap]
keywords: [工具, keyMap]
---

当我使用笔记本的时候，每次移动光标，都要大费周章，同时由于笔记本的缘故，导致键入Home与End都需要搭配Fn功能键来实现。所以我希望在任何情况下（敲代码，写文章）都可以将某些组合键绑定为上下左右键，在代码编辑器上有键盘映射可以设置，但脱离代码编辑器就不起作用了，在window下有个神器 [AutoHotkey](https://www.autohotkey.com/) 可以实现我想要的功能。

<!-- truncate -->

## 安装

打开[官网](https://www.autohotkey.com/)，点击Download，安装即可。

## 使用

安装完成后，右键新建会AutoHotKey Srcipt后缀为ahk。例如创建demo.ahk，其内容如下

```ahk
<+<!I::Send {Up} 
<+<!K::Send {Down} 
<+<!J::Send {Left} 
<+<!L::Send {Right} 
<+<!H::Send {Home} 
<+<!;::Send {End} 
```

然后保存双击该文件，即可运行autohotkey，此时打开任意文本，键入<kbd>Shift</kbd> + <kbd>Ctrl</kbd> + [HIJKL;] 就可以看到光标上下左右移动。

这里对上面语法进行讲解

| 键名  | 热键标识 |
| ----- | -------- |
| Ctrl  | ^        |
| Shift | +        |
| Alt   | !        |
| Win   | #        |

如果要针对左右Ctrl或Shfit只需要在前面添加`<` `>` 。`::`则作为映射关系，左边的按键作用于何种指令，而右侧则是左侧按键所对应的指令，这里的指令相对简单，只是发送键盘上下左右的关系，指令还可以实现信息框MsgBox 启动应用等等。具体还有更多键盘与鼠标热键详情可在AutoHotkey Help手册中查看，非常详细，不过是英文。

具体要映射的快捷键可自行发挥，但要切记不建议与常用快捷键冲突，例如上面为何是IJKL而不是WASD，其原因会导致快捷键冲突。

此外AutoHotkey不仅能做键盘映射，实现宏定义，一键启动任务也不成问题，篇幅有限，就不做过多演示，有兴趣可自行研究。



