---
title: Frida笔记
date: 2020-02-02
tags:
  - frida
  - app
draft: true
---

## 虚拟环境安装

由于 Python 版本兼容性问题，建议是安装虚拟环境

#### 安装 virtualenvwrapper

```
pip install virtualenvwrapper-win -i https://pypi.tuna.tsinghua.edu.cn/simple
```

#### 创建虚拟环境

```
# mkvirtualenv --python=python版本路径 环境名

mkvirtualenv --python=E:\Python37\python.exe py37
mkvirtualenv --python=E:\Python38\python.exe frida

```

默认是用户路径下`C:\Users\zeyu\Envs\kuizuo`

#### 添加虚拟环境变量

添加一个 `WORKON_HOME` 为 `E:\Envs`

#### 进入虚拟环境

```
workon  #列出所有虚拟环境

workon 环境名  #进入对应名字下的虚拟环境
```

#### 退出虚拟环境

```
deactivate
```

## 安装 frida

frida python 库

frida-tools

fridaserver

```
pip install frida-tools  # 会自动帮你下载Frida 最新版
```

然而要科学上网，不然大概率是下载不了的，索引就需要下载对应的 whl 文件，直接离线安装

下载 setuptools-46.0.0-py3-none-any.whl
https://pypi.org/project/setuptools/#modal-close

下载 frida-12.8.14-py3.7-win-amd64.egg
https://pypi.org/project/frida/#files

easy_install frida-12.8.14-py3.7-win-amd64.egg

### frida 代码提示

```
npm i @types/frida-gum
```

### fridaserver 安装

我们需要下载的文件名的格式是： frida-server-(version)-(platform)-(cpu).xz 解压后内的文件 push 到手机内

我测试的手机是 Pixel, cpu 为 arm64

```
adb push C:\Users\zeyu\Desktop\frida-server-12.11.7-android-arm64 /data/local/tmp/fsarm64

adb shell
su
cd data/local/tmp
chmod 777 fsarm64

./fsarm64
```

### fridaserver 使用

```
./data/local/tmp/fsarm64  # 启动fs服务
# 可以携带参数 -l address:port 监听地址  就无需转发端口

# adb forward tcp:27042 tcp:27042 # 另开一个CMD进行端口转发

workon frida #进入frida环境
...

frida -H 设备IP:端口 #这里就要以-H HOST的形式去连接 192.168.137.89:9999

```

总结下来也就是

```
./data/local/tmp/fsarm64 -l 0.0.0.0:9999

workon frida
frida -H 192.168.137.89:9999 -F -l demo.js

frida -U -F -l demo.js
```

## frida 基本命令

frida -help 查看帮助

主要就这几个命令

##### frida-ps 打印进程信息 -U 打印手机设备

在这个命令下查看进程包名看是最准确的

##### -U,–usb 连接 USB 设备

##### -F, --attach-frontmost 以 app 最前的应用进行 Hook

##### -l SCRIPT, --load=SCRIPT 以 js 脚本方式注入

```
frida -U 包名 -l js文件

#将会打印
(frida) F:\Frida\Fridastudy>frida -U com.dodonew.online -l Hook.js
     ____
    / _  |   Frida 12.11.7 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/
Attaching...
i am frida
[Pixel::com.dodonew.online]-> exit

Thank you for using Frida!
```

**注：**Frida 不支持 es6 语法，也就是无法使用 let 声明变量

```js
// java层的代码 都需要在perform下执行
Java.perform(function () {
  // Java.use()   // 选择对应的类名 返回实例化的对象  可直接调用类下方法(反编译后查看)
  var RequestUtil = Java.use('com.dodonew.online.http.RequestUtil');

  // 调用类下的md5方法 同时实现方法改为新函数
  RequestUtil.md5.implementation = function (a) {
    console.log('a', a);
    var ret = this.md5(a);
    console.log(ret);
    return ret;
  };

  // 对于构造函数 则需要添加overload,同时添加类型
  RequestUtil.encodeDesMap.overload('java.lang.String').implementation;
});
```

## fridaApi

TODO...

### Objection 的安装

`pip install frida==12.11.7 pip install frida-tools==8.1.3`
`pip install objection==1.9.6`

`Frida`只是提供了各种`API`供我们调用，在此基础之上可以实现具体的功能，比如禁用证书绑定之类的脚本，就是使用`Frida`的各种`API`来组合编写而成。于是有大佬将各种常见、常用的功能整合进一个工具，供我们直接在命令行中使用，这个工具便是`objection`。

`objection`功能强大，命令众多，而且不用写一行代码，便可实现诸如内存搜索、类和模块搜索、方法`hook`打印参数返回值调用栈等常用功能，是一个非常方便的，逆向必备、内存漫游神器。

TODO...
