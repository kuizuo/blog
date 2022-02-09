---
title: objection笔记
date: 2021-02-10
authors: kuizuo
tags: [frida,app,hook]
---

## objection

Frida只是提供了各种API供我们调用，在此基础之上可以实现具体的功能，比如禁用证书绑定之类的脚本，就是使用Frida的各种API来组合编写而成。于是有大佬将各种常见、常用的功能整合进一个工具，供我们直接在命令行中使用，这个工具便是[objection](https://github.com/sensepost/objection)。

objection功能强大，命令众多，而且不用写一行代码，便可实现诸如内存搜索、类和模块搜索、方法hook打印参数返回值调用栈等常用功能，是一个非常方便的逆向必备、内存漫游神器。

### 安装

```sh
pip install objection
```

### 使用

```sh
objection -g <包名> explore
objection -N -h <手机ip地址> -p <端口> -g <包名> explore # 指定ip与端口连接
```

#### 选项

| 选项                             | 功能               |
| -------------------------------- | ------------------ |
| -s, --startup-command “hook命令” | 启动前注入         |
| -c, –file-commands FILENAME      | 通过文件命令来运行 |
| --dump-args                      | 打印参数           |
| --dump-return                    | 打印返回值         |
| --dump-backtrace                 | 打印堆栈信息       |


objection log文件位置: `C:\Users\zeyu\.objection\objection.log`

### 常用命令

| 命令      | 功能                |
| --------- | ------------------- |
| frida     | 显示frida版本信息   |
| env       | 显示app相关环境变量 |
| help 命令 | 查看命令帮助        |

#### hook命令

| 命令                                                         | 功能                             |
| ------------------------------------------------------------ | -------------------------------- |
| `android hooking list classes`                               | 列出所有已加载的类               |
| `android hooking search classes <pattern>`                   | 搜索特定关键字的类               |
| `android hooking list class_methods <路径.类名>`             | 列出类下所有方法                 |
| `android hooking watch class <路径.类名>`                    | hook类的所有方法(不包括构造方法) |
| `android hooking watch class_method <路径.类名.方法名>`      | hook类的方法(所有重载方法)       |
| `android hooking watch class_method <路径.类名.方法名> "<参数类型>"` | hook单个重载方法，需指定参数类型 |

#### 查看hook列表

```
jobs list
```

#### 取消hook

```
jobs kill <jobId>
```

#### 关闭ssl效验

```
android sslpinning disable
```

#### 关闭root检测

```
android root disable
```

### 界面跳转

#### 查看当前app的activity

```
android hooking list activities
```

#### 尝试跳转到对应的activity

```
android intent launch_activity <activityName>
```

### 插件

#### 加载插件

```
objection -g com.app.name explore -P <插件路径>
```

or

```
objection -g com.app.name explore
plugin load <插件路径>
```

#### [Wallbreaker](https://github.com/hluwa/Wallbreaker)

从内存中搜索对象或类，并漂亮地可视化目标的真实结构。

```
objection -g com.app.name explore -P F:\Frida\objection-plugin\Wallbreaker\wallbreaker
// or
plugin load F:\Frida\objection-plugin\Wallbreaker\wallbreaker
```

##### 使用

```
plugin wallbreaker classsearch <pattern>  # 搜索类
plugin wallbreaker objectsearch <classname> # 搜索类的实例对象
plugin wallbreaker classdump <classname> [--fullname] # 输出类结构， 打印数据中类的完整包名
plugin wallbreaker objectdump <object-handle> [--fullname] # 输出指定对象的每个字段值

```

#### [FRIDA-DEXDump](https://github.com/hluwa/FRIDA-DEXDump)

进入objection，加载插件 plugin load <插件路径> [指定插件名字]

注意路径斜杠

```
plugin load F:\\Frida\objection-plugin\\FRIDA-DEXDump\\frida_dexdump 

# 加载完插件后就可以使用插件命令了

plugin dexdump dump
plugin dexdump search
```