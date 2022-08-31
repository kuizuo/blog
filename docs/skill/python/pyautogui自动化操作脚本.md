---
id: pyautogui
slug: /pyautogui
title: pyautogui自动化操作脚本
date: 2022-02-18
authors: kuizuo
tags: [python, script, auto]
keywords: [python, script, auto]
---

<!-- truncate -->

说实话，貌似有一年没写过啥脚本类的代码了

之前针对加密视频播放编写了一个自动答题的脚本（使用易语言 大漠插件所编写的）

![image-20220207045652164](https://img.kuizuo.cn/20220207045652.png)

还有商户自动话术回复的（也是易语言+大漠插件）

![image-20220207050011838](https://img.kuizuo.cn/20220207050011.png)

还有使用 autojs 所编写的一个针对安卓端钉钉的自动签到

![image-20220207045811771](https://img.kuizuo.cn/20220207045811.png)

还有一个某宝领喵币类的，这里就不放截图了

甚至是一些网页类的脚本，例如油猴，Chrome 拓展之类的，都可以算作是脚本开发。

通常对这类代码称 RPA(机器人流程自动化)，不过自从玩了网络协议后，貌似就没在怎么碰过自动化操作脚本类的东西了（协议 脱机是真香，并且效率还高，不过需要一定的逆向能力），但对于一些需要自动化的东西，就只能靠脚本了。

## 使用

pyautogui 无就是一个 python 版的针对 windows 的 API 的封装操作，而这类操作主要功能就是找到窗口，找到鼠标位置，控制鼠标点击移动，还有键盘信息输入，进行一系列流程控制来达到想要的目的。所以必然会提供相关的 API 供调用，这里有一篇文章 [PyAutoGUI 超全介绍|基于 python 的自动化控制|工作自动化](https://www.zhaoyabo.com/?p=7033#i-15) 就不做 api 的介绍了。

## 例子

就简单写一个打开微信窗口并自动寻找关键人物头像发送你好的例子，顺便来说明下编写一个自动化脚本的各个流程。

### 第一步：寻找窗口

如果要写一个自动化脚本，首先范围是一定要确认好，这样能避免不必要的区域搜索以及效率的提升，在这里例子的范围就是整个微信窗口，通过一些窗口检测工具（这里使用精易编程助手），可以得到窗口标题与窗口类名，用于定位窗口（**窗口句柄**）。

![image-20220218065420228](https://img.kuizuo.cn/20220218065420.png)

可以通过如下代码获取窗口句柄

```python
def findWindow():
    windows = pyautogui.getWindowsWithTitle('微信')
    if len(windows) == 0:
        raise Exception("微信窗口未找到")
    return windows[0]


wxWindow = findWindow()
wxWindow.activate() # 激活窗口,将窗口最前化
```

### 第二步：找图点击

要找到对应联系人，就需要找到该联系人的相关特征，例如头像、昵称，这里就以头像作为演示。

既然要以头像作为特征，那么就需要提前将头像保存起来，然后利用 api 找到图片所在的坐标

```python
def clickAvatar():
    try:
        location = pyautogui.locateOnScreen('avatar.png')
        print(location)  # Box(left=293, top=402, width=40, height=40)
        pyautogui.click(location)
        # pyautogui.click('avatar.png') # 坐标用不到的话，可使用该命令 识图+点击
    except:
        print('头像未找到')
```

要注意的是：头像最好截取的完整（小而准），因为要完全匹配（所有像素及分辨率）。

### 第三步：输入内容

经过上面两步操作，就可以正常打开对应联系人与其聊天，现在就需要将内容输入到聊天框，然后和第二步一样找到发送按钮并点击。

```python
import pyperclip


def paste(content):
    pyperclip.copy(content)
    pyautogui.hotkey('ctrl', 'v')


content = u'你好'
paste(content)
```

由于我们要输入的内容是包含中文的，而在一般键盘指令是无法直接输入中文，所以需要变通一下，将所需要输入的内置剪辑版，然后使用组合键 ctrl + V 粘贴至窗口，具体代码如上演示（需要引入 pyperclip）

然后同第二步，找到发送按钮，并点击

```python
def clickSend():
     pyautogui.click('send.png')
```

### 完整代码

```python
import pyperclip
import pyautogui

pyautogui.PAUSE = 1 # 调用在执行动作后暂停的秒数，只能在执行一些pyautogui动作后才能使用，建议用time.sleep

def findWindow():
    windows = pyautogui.getWindowsWithTitle('微信')
    if len(windows) == 0:
        raise Exception("微信窗口未找到")
    return windows[0]


def clickAvatar():
    try:
        location = pyautogui.locateOnScreen('avatar.png')
        print(location) # Box(left=293, top=402, width=40, height=40)
        pyautogui.click(location)
        # pyautogui.click('avatar.png')  # 坐标用不到的话，可使用该命令
    except:
        print('头像未找到')

def clickSend():
     pyautogui.click('send.png')


def paste(content):
    pyperclip.copy(content)
    pyautogui.hotkey('ctrl', 'v')


if __name__ == '__main__':
    wxWindow = findWindow()
    wxWindow.activate()  # 激活窗口,将窗口最前化
    clickAvatar()

    content = '你好'
    paste(content)

    clickSend()
```

## 演示效果

![wxauto](https://img.kuizuo.cn/wxauto.gif)

## 体验感受

不过还有很多地方需要改进，例如多个微信窗口的情况下呢，针对窗口的操作更推荐使用 win32gui，其次在找图的时候，使用的是全屏找图，但都已经找到图片所在的区域是微信窗口的大小，可以将范围搜下，以便搜到更快。

上面也仅仅只是一个简单的例子，事实上自动化所需要考虑的东西挺多的，比方我当时编写的视频自动答题的，就需要定时（1 秒）监控是否弹出答题窗口，然后判断题目内容，从现有题库中获取题库。而不是像上面这个看似毫无意义，实际也确实毫无意义，但如果对其加强，比方说判断微信图标是否闪烁（有人发消息），然后对对方的聊天内容进行判断是否有关键词进行回复，事实上就能做一个简单的机器人客服聊天了（对于一些平台不支持自动回复的话，自动化脚本有显得很有用了）。不过具体使用场景还需要另行考虑，本文所展示的例子看看就行了。

不过整体体验下来，该说不说，比易语言好太多了，如果再让我写 window 窗口自动化操作的话，我肯定毫不犹豫的选择 python 来编写。
