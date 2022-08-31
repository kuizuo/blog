---
id: windows-custom-right-click-menu
slug: /windows-custom-right-click-menu
title: Windows自定义右键菜单
date: 2020-09-08
authors: kuizuo
tags: [工具]
keywords: [工具]
---

为什么写这篇文章呢，因为我每次都要更改鼠标右键菜单都要去百度相关的，然后在照着一步一步操作。甚至我在写这篇文章的时候也百度了相关的内容。到时候忘记了直接看我自己写的就完事了（可能写了之后就记得住了。）

<!-- truncate -->

## 开始操作

### 打开注册表

要修改右键菜单的内容，就需要打开注册表。修改注册表的内容，来为右键菜单增添一些内容。

打开运行(Windows 键＋ R)，输入 regedit，点击确定打开注册表。

​ ![image-20200908114639158](https://img.kuizuo.cn/image-20200908114639158.png)

这里建议右键 文件->导出，以防不小心误操作还原为原先配置。

接着可以在 编辑 -> 查找 (Ctrl+F)，接着搜索对应的关键词。输入要查找的目标的值，具体操作会在后面详细说明。

![image-20200908154701753](https://img.kuizuo.cn/image-20200908154701753.png)

### 右键打开 Cmd

最终效果，右键空白处，可以使用打开 CMD，如图

![image-20200908152557371](https://img.kuizuo.cn/image-20200908152557371.png)

用于你在对应的文件夹下输入 cmd 命令，免去 cd 等繁杂操作。个人建议设置一下，将下面的代码复制，然后创建一个`1.reg`文件（文件名无所谓，后缀名是 reg 就行，**注意保存为 ANSI**，不然带中文会乱码）,点击运行，会有提示，放心，绝对安全。接着右键空白处，就可也看到打开 CMD 的字样，点击就能打开 cmd 窗口。

```shell
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\background\shell\cmd_here]

@="打开 CMD"
"Icon"="cmd.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\background\shell\cmd_here\command]

@="\"C:\\Windows\\System32\\cmd.exe\""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\shell\cmdPrompt]

@="打开 CMD"
"Icon"="cmd.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\shell\cmdPrompt\command]

@="\"C:\\Windows\\System32\\cmd.exe\" \"cd %1\""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\cmd_here]

@="打开 CMD"
"Icon"="cmd.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\cmd_here\command]

@="\"C:\\Windows\\System32\\cmd.exe\""
```

### 右键空白区域的菜单

有的时候安装了一个开发软件，不小心勾上了什么`open Folder as …`然后就出现下图情况

![image-20200908115455647](https://img.kuizuo.cn/image-20200908115455647.png)

但有时候我并不需要这么长的选项，或者说我想改一下名字，让他不那么长。这时候我们同样打开注册表，首先这是*右键在文件夹空白处下*的（桌面也是一个文件夹，路径是 C:\User\用户名\Desktop）那么对应的注册表的位置是 `计算机\HKEY_CLASSES_ROOT\Directory\Background\shell` （或搜索对应的关键词），输入完定位目录为下图![image-20200908151408855](https://img.kuizuo.cn/image-20200908151408855.png)

看到画框的 IDEA 没，那就是 IDEA 安装的时候为用户添加的右键菜单，现在我不要这个右键菜单，那就把这个文件夹整个删了就行（这里推荐你删了，太占空间了）。但这时我只想改一下右键菜单的文件名，不想让他这么长，那么你在默认哪里鼠标右键，选择修改，然后输入修改后的文件名即可。而下面的 Icon 则是图标路径，对应的也就是 exe 路径。如果图标没了，那么多半就是这里的问题。

然后在`IntelliJ IDEA`下还有一个 command 目录，这个目录就一个默认，对应的是执行文件的命令，你会看到一个是文件路径 可能还有一个参数是 `”%V“` ，意思就是如果你这个运行时没有传参默认就是你工作目录。可以查看 [windows 帮助](https://superuser.com/questions/136838/which-special-variables-are-available-when-writing-a-shell-command-for-a-context)

### 右键文件夹菜单

![image-20200908152835802](https://img.kuizuo.cn/image-20200908152835802.png)

本以为上面设置好删除了`Open Folder as IntelliJ IDEA Project` 这个长的要死的文件夹，没想到右键文件夹竟然也有，不管了定位在对应的位置再说，路径 `计算机\HKEY_CLASSES_ROOT\Directory\shell`，我擦，原来就在上一步操作的文件夹的下面一点。定位的结果如下

![image-20200908153930520](https://img.kuizuo.cn/image-20200908153930520.png)

然后同上一步操作，这里修改一下名字就行，我就设置短点名字`Open Folder as IDEA`。结果如下

![image-20200908154339744](https://img.kuizuo.cn/image-20200908154339744.png)

### 右键程序菜单

既然上两步的操作你都会了，那么右键程序菜单也是一样，定位到对应的路径`计算机\HKEY_CLASSES_ROOT\*\shell\` 我就放一张定位路径图。

![image-20200908164515142](https://img.kuizuo.cn/image-20200908164515142.png)

### 右键手动新建

现在你应该知道如何定位到已有的右键菜单，并且知道了如何修改或者删除。那么现在，就手动来新建一个右键菜单。

作为一个`vscode`使用者，右键不设置`通过 Code 打开`怎么行，而你安装了`vscode`却没有`Open with Code`，那就是你安装时没有勾上这两项。

![20190530203030700](https://img.kuizuo.cn/20190530203030700.png)

当然你也可以百度 右键菜单添加 vscode，会有相关像我提供的右键`打开 Cmd`这样的操作。这里也将对应代码贴出来，但*需要更改一下的 vscode 的路径*与右键菜单名，并且要将单反斜杠都换成双反斜杠 防止转义。例如，这里右键菜单名为`Open with Code`，而我的`Code.exe`路径为`E:\VSCode\Code.exe`那么我就要改为`E:\\VSCode\\Code.exe`，你只需要改为你的路径即可。

zhuyi 下面有的路径是在`Code.exe`后面有一个`\`这里是转义`“`的，不要删除。所以这么麻烦，还不如重新卸载安装勾上这两个选项。

按同样的存为`1.reg`文件，双击执行即可

```shell
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\*\shell\VSCode]
@="Open with Code"
"Icon"="E:\\VSCode\\Code.exe"

[HKEY_CLASSES_ROOT\*\shell\VSCode\command]
@="\"E:\\VSCode\\Code.exe" \"%1\""

[HKEY_CLASSES_ROOT\Directory\shell\VSCode]
@="Open with Code"
"Icon"="E:\\VSCode\\Code.exe"

[HKEY_CLASSES_ROOT\Directory\shell\VSCode\command]
@="\"E:\\VSCode\\Code.exe\" \"%V\""

[HKEY_CLASSES_ROOT\Directory\Background\shell\VSCode]
@="Open with Code"
"Icon"="E:\\VSCode\\Code.exe"

[HKEY_CLASSES_ROOT\Directory\Background\shell\VSCode\command]
@="\"E:\\VSCode\\Code.exe\" \"%V\""
```

不过这里还是说下手动的操作，话不多说先看 gif 操作

![demo](https://img.kuizuo.cn/demo.gif)

由于我设置过了 VSCode，这里我将 S 改成 B，对应的操作就是这样。对应的数据我在上面也已经说过了。一般来说也没必要手动操作添加，都会有对应的`.reg`文件，点击运行即可。

## 这里补充一个

右键菜单有一个自定义文件夹，这个没什么用可以通过注册表来进行删除。

#### 1.首先打开注册表

#### 2.定位到`计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`

#### 3.然后右键新建 DWORD，名称为`NoCustomizeWebView`，数值为 1。

![image-20200908163225915](https://img.kuizuo.cn/image-20200908163225915.png)

#### 4.打开任务管理器，找到 Windows 资源管理器，右键重新启动，再次打开就会发现右键不在有自定义文件夹了。

![image-20200908163415434](https://img.kuizuo.cn/image-20200908163415434.png)

## 总结

- 右键文件夹空白处所对对应的目录路径是`计算机\HKEY_CLASSES_ROOT\Directory\Background\shell`

- 右键文件夹的目录路径是`计算机\HKEY_CLASSES_ROOT\Directory\shell`

- 右键程序的目录路径是 `计算机\HKEY_CLASSES_ROOT\*\shell`

**要添加，要修改就因人而异了。**
