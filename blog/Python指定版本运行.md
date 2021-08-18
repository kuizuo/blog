---
id: Python指定版本运行
title: python指定版本运行
date: 2020-09-11
tags:
 - python
---

<!-- truncate -->

## 前言

在用一些开源的python脚本的时候，而原作者是用`python2.7`写的，但学过python的应该会知道python每个版本之间存在兼容性，python2的代码用python3是会可能运行不了的，一些现有的框架在python3.6可以运行而python3.7就报错。通常这时候我想执行python2代码的解决办法：

- 安装python2，并且就算安装了还要重新配置环境变量这些（麻烦）
- 通过虚拟环境，来安装python2，在虚拟环境中运行python2代码（麻烦)
- python3(>=3.3)其实自带了python2的代码，就没必要像上面那么麻烦

### 具体实现步骤

其实在安装Python3（>=3.3）时，Python的安装包实际上在系统中安装了一个启动器`py.exe`，默认放置在文件夹`C:\Windows\`下面。这个启动器允许我们指定使用Python2还是Python3来运行代码。

![image-20200912224056257](https://img.kuizuo.cn/image-20200912224056257.png)

例如：

#### 运行python2

```sh
py -2 demo.py
```

![image-20200912225223752](https://img.kuizuo.cn/image-20200912225223752.png)

#### 运行python3

```sh
py -3 demo.py
```

![image-20200912225250066](https://img.kuizuo.cn/image-20200912225250066.png)

只要把命令行的python的改成py -2 就能以python2来执行。 但是，每次运行都要加入参数-2和-3还是比较麻烦，于是所以py.exe这个启动器允许你在代码中加入说明，表明这个文件应该是由python2或3来解释运行。只需要在代码文件的最开始加入一行，**一定要放到文件第一行**，编码可以放在第二行，如

```py
#!py -2
# -*- coding: utf-8 -*- 

...code
```

### pip安装

#### python2下安装

```sh
py -2 -m pip install XXXX
```

#### python3下安装

```sh
py -3 -m pip install XXXX
```