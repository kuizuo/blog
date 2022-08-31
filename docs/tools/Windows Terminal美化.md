---
id: windows-terminal-beautify
slug: /windows-terminal-beautify
title: Windows Terminal美化
date: 2021-05-04
authors: kuizuo
tags: [Terminal, 美化]
keywords: [Terminal, 美化]
---

![image-20210527065050479](https://img.kuizuo.cn/image-20210527065050479.png)

<!-- truncate -->

其实就是美化 PowerShell 命令窗口罢了，同时可以判断当前目录下的语言环境，还有标签，时间（没错，这是我早上 6 点 40 左右写的一篇文章），等等，（顺便吐槽一句，没想到 python 都发布到了 3.9.5）

## 安装

在 Microsoft Store 搜索 Windows Terminal，点击安装即可。

win + R 输入 `wt` 即可启动 Terminal

或者右键文件夹空白处 `Open in Windows Terminal`

不过默认设置背景全黑 同时 打开配置文件

![image-20210527070628394](https://img.kuizuo.cn/image-20210527070628394.png)

其中在 profiles.list 下则是对应不同的终端，默认有 Windows PowerShell，Command Prompt，AzureCloud Shell，

这边主要优化的是 Windows PowerShell

### 更改 powershell

如下是我的配置文件

```
{
"acrylicOpacity": 0.69999999999999996,
"commandline": "powershell.exe -nologo",
"fontFace": "JetBrainsMono NF",
"fontSize": 10,
"guid": "{61c54bbd-c2c6-5271-96e7-009a87ff44bf}",
"hidden": false,
"name": "Windows PowerShell",
"useAcrylic": true
},
```

- useAcrylic: `true` 毛玻璃效果 如果是图片的话 就别用毛玻璃的
- acrylicOpacity: `0.7` 透明度
- fontFace: `JetBrainsMono NF` 字体 这里我用的是 jetbrains 家的，强烈推荐
- fontSize: `10` 字体大小

[字体下载](https://github.com/ryanoasis/nerd-fonts/tree/master/patched-fonts) 不过估计要翻墙才能下载，下载 windows 的 .ttf 然后双击 安装即可

### 下载模块

**管理员**方式打开 PowerShell，输入如下命令

设置组权限，不然安装不了所需的模块

```shell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

下载`oh-my-posh` 和`posh-git` 这边估计也要翻墙，不然大概率下载不了。

```shell
Install-Module oh-my-posh -Scope CurrentUser
Install-Module posh-git -Scope CurrentUser
Install-Module Get-ChildItemColor -Scope CurrentUser
```

提示输入选择 是（Y）或者 全是（A）

### 安装主题

下载完毕输入下方命令 打开预览主题

```shell
Get-PoshThemes
```

![image-20210527071827101](https://img.kuizuo.cn/image-20210527071827101.png)

貌似上面的主题混入了某个不显眼的字样

临时切换某个主题

```shell
Set-PoshPrompt jandedobbeleer
```

和我目前这个有点小像（因为当时是基于 jandedobbeleer 这个主题改的），不过这只是临时主题，需要更改主题文件，路径一般为 `C:\Users\用户名\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`

或者输入下方命令来打开

```
$profile
if (!(Test-Path -Path $PROFILE )) { New-Item -Type File -Path $PROFILE -Force }
notepad $PROFILE
```

添加下方代码并保存，重启 Terminal 即可生效

```shell
Import-Module Get-ChildItemColor
$env:PYTHONIOENCODING="utf-8"
Import-Module posh-git
Import-Module oh-my-posh

$DefaultUser = 'kuizuo'
# Set theme
Set-PoshPrompt jandedobbeleer
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
```

### 修改主题

官方预设的主题，并不满足于我，于是就去查阅了官方文档 [Introduction | Oh my Posh](https://ohmyposh.dev/docs/)

首先，官方的主题所在的路径 为 `C:\Users\用户名\Documents\WindowsPowerShell\Modules\oh-my-posh\3.144.0\themes`

在`themes`目录下新建文件`xxxx.omp.json` 比如 `kuizuo.omp.json`

我是基于主题 jandedobbeleer 所更改的，所以有些相似，这边就放一下我的主题文件配置，具体的参数 需要查看对应的官方文档，这里就不过多叙述了。

```json
{
  "$schema": "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/schema.json",
  "blocks": [
    {
      "type": "prompt",
      "alignment": "left",
      "segments": [
        {
          "type": "os",
          "style": "diamond",
          "foreground": "#ffffff",
          "background": "#3A86FF",
          "leading_diamond": "\uE0B6"
        },
        {
          "type": "session",
          "style": "powerline",
          "foreground": "#ffffff",
          "background": "#3A86FF",
          "properties": {
            "postfix": " ",
            "display_host": false
          }
        },
        {
          "type": "git",
          "style": "powerline",
          "powerline_symbol": "",
          "foreground": "#193549",
          "background": "#fffb38",
          "properties": {
            "display_stash_count": true,
            "display_upstream_icon": true,
            "status_colors_enabled": true,
            "local_changes_color": "#ff9248",
            "ahead_and_behind_color": "#f26d50",
            "behind_color": "#f17c37",
            "ahead_color": "#89d1dc",
            "stash_count_icon": "\uF692 "
          }
        },
        {
          "type": "node",
          "style": "powerline",
          "powerline_symbol": "\uE0B0",
          "foreground": "#ffffff",
          "background": "#6CA35E",
          "properties": {
            "prefix": " \uE718 "
          }
        },
        {
          "type": "go",
          "style": "powerline",
          "powerline_symbol": "",
          "foreground": "#111111",
          "background": "#8ED1F7",
          "properties": {
            "prefix": " \uE626 ",
            "display_version": true
          }
        },
        {
          "type": "python",
          "style": "powerline",
          "powerline_symbol": "",
          "foreground": "#111111",
          "background": "#FFDE57",
          "properties": {
            "prefix": " \uE235 ",
            "display_version": true,
            "display_mode": "files",
            "display_virtual_env": false
          }
        },
        {
          "type": "path",
          "style": "powerline",
          "powerline_symbol": "\uE0B0",
          "foreground": "#ffffff",
          "background": "#61AFEF",
          "properties": {
            "prefix": " \uE5FF ",
            "style": "full"
          }
        },
        {
          "type": "exit",
          "style": "powerline",
          "powerline_symbol": "\uE0B0",
          "foreground": "#ffffff",
          "background": "#ff8080",
          "properties": {
            "prefix": " \uE20F"
          }
        }
      ]
    },
    {
      "type": "rprompt",
      "segments": [
        {
          "type": "ytm",
          "style": "powerline",
          "powerline_symbol": "\uE0B2",
          "invert_powerline": true,
          "foreground": "#111111",
          "background": "#1BD760",
          "properties": {
            "prefix": " \uF167 ",
            "paused_icon": " ",
            "playing_icon": " "
          }
        },
        {
          "type": "battery",
          "style": "powerline",
          "invert_powerline": true,
          "powerline_symbol": "\uE0B2",
          "foreground": "#ffffff",
          "background": "#f36943",
          "properties": {
            "battery_icon": "",
            "discharging_icon": " ",
            "charging_icon": " ",
            "charged_icon": " ",
            "color_background": true,
            "charged_color": "#4caf50",
            "charging_color": "#40c4ff",
            "discharging_color": "#ff5722",
            "postfix": " "
          }
        },
        {
          "type": "time",
          "style": "diamond",
          "invert_powerline": true,
          "leading_diamond": "\uE0B2",
          "trailing_diamond": "\uE0B4",
          "background": "#2e9599",
          "foreground": "#111111",
          "properties": {
            "time_format": "15:04:05",
            "prefix": "<#000000> \uf64f </>"
          }
        }
      ]
    }
  ],
  "final_space": true
}
```

然后将设置主题的命令 改为 主题名 比如

```shell
 Set-PoshPrompt kuizuo
```

之后你的 PowerShell 就和我这个一样了。

### 添加 GitBash

这里的`E:/Git` 是我的 git 的安装路径，可根据你的自行更改

```json
{
  "hidden": false,
  "name": "Git Bash",
  "commandline": "E:/Git/bin/bash.exe -li",
  "icon": "E:/Git/mingw64/share/git/git-for-windows.ico",
  "startingDirectory": "%USERPROFILE%"
}
```

## 最后

当时在技术群里看到大佬秀 termnial 美化 于是自己也去折腾了一番，也折腾了一个晚上，不过好在最终效果还是比较满意的。就是不知道会不会再去折腾 Windows 桌面的美化了，算了我还是换个背景得了。

贴几个相关链接

[究极美化之 posh+termnial – 翻车鱼 (shi1011.cn)](https://blog.shi1011.cn/other/957)

[Windows 终端概述 | Microsoft Docs](https://docs.microsoft.com/zh-cn/windows/terminal/)

[Introduction | Oh my Posh](https://ohmyposh.dev/docs/)
