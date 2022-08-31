---
slug: thinkphp-deploy
title: 记 ThinkPHP 项目部署
date: 2021-09-25
authors: kuizuo
tags: [php, develop]
keywords: [php, develop]
---

<!-- truncate -->

## 事情背景

用户花了几百块购买了一份 ThinkPHP 一个后台管理的网站源码，要求更换下部分失效接口，或是重写一个类似这样的网站。我想既然都有源码了，我改改不就完事了，这不比重写一个来的省事。虽说我不是主学 PHP 的，但至少我学过一丢丢的 PHP，接触过 ThinkPHP 项目的。不过层面都是局限在本地，部署到生产环境与本地还是有比较大的差别的，于是便有了这篇文章来记录一下自己部署 ThinkPHP 所遇到的一些坑。

## Windows 部署

也可理解为本地部署，本地部署就相对比较简单的了。不过需要一个工具，PHPStudy，来帮助我们配置本地的环境（Apache、Nginx、PHP、Mysql）

[小皮面板(phpstudy) - 让天下没有难配的服务器环境！ (xp.cn)](https://www.xp.cn/)

下载安装打开界面，选择网站，创建网站

![image-20210925143601530](https://img.kuizuo.cn/image-20210925143601530.png)

由于是本机，所以域名就填写 localhost 或 127.0.0.1，端口的话这边所填写的是 4200，别和其他端口冲突即可。

由于 ThinkPHP 的根目录要选择的是根目录下的 public 目录，不然找不到 index.php 这个文件，所以这里根目录自己指定一下源码的位置，点击确认即可。

### 初次启动 Not Found

这时候访问 http://localhost:4200 提示如下

![image-20210925143752775](https://img.kuizuo.cn/image-20210925143752775.png)

本着不会就百度的原则，很快就找到了解决办法

[ThinkPHP 报错 The requested URL /index/index/xxx.html was not found on this server](https://blog.csdn.net/qq_42940241/article/details/112461625)

在入口文件夹 public 下查看.htaccess 是否存在。不存在则新建，存在的话，那内容替换为下面这串代码 就可以解决 Not Fund 问题

```xml
#<IfModule mod_rewrite.c>
#  Options +FollowSymlinks -Multiviews
#  RewriteEngine On
#
#  RewriteCond %{REQUEST_FILENAME} !-d
#  RewriteCond %{REQUEST_FILENAME} !-f
#  RewriteRule ^(.*)$ index.php/$1 [QSA,PT,L]
#</IfModule>
<IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^(.*)$ index.php?/$1 [QSA,PT,L]
</IfModule>
```

### 页面报错 开启 Debug

上面配置完毕后，再次打开出现如下提示。

![image-20210925144143248](https://img.kuizuo.cn/image-20210925144143248.png)

遇到错误是很正常的，现在要做的就是输出报错信息，而不是简短的文字。到根目录下 config/app.php 中，将调试更改为 true（切记，生产环境中一定要更改为 false，不然用户就能查看报错详情以及对应代码）

![image-20210925144424361](https://img.kuizuo.cn/image-20210925144424361.png)

### 配置数据库

再次访问页面提示

**![image-20210925144620953](https://img.kuizuo.cn/image-20210925144620953.png)**

报错信息倒是很全，不过要关注的是报错行和提示，大致意思就是没有定义数据库用户名 ml 以及密码，毕竟数据库啥的都好像没配置，要是能启动起来那估计就真是一个 bug 了，那就先找到配置文件，看看原本的账号密码是多少，数据库配置文件位置`config/database.php`

![image-20210925145740851](https://img.kuizuo.cn/image-20210925145740851.png)

不过 PHPstudy 用户名和密码长度都要在 6 位以上（Linux 倒是不用），所以勉为其难，把用户名和密码都改成 ml1234，接着 Mysql 导入源码给定的数据库文件(sql 文件)，什么，你说源码没有给数据库文件，那我建议直接删源码，并且接下来的内容也可以不用看了。

数据库导入完毕后，再次访问便能看到正常的首页了，就此就算部署完毕了，这里就不放首页图了。

## Linux 部署

Linux 部署和 Windows 部署是有一丢丢差别的，这里我也列举一下，环境是 CentOS 7.6，安装了宝塔面板

在宝塔面板出网站，添加网站，如同 PHPstudy，配置大致相同。

![image-20210926050508693](https://img.kuizuo.cn/image-20210926050508693.png)

### 关闭防跨站攻击

情况 1，如图

![image-20210925155027023](https://img.kuizuo.cn/image-20210925155027023.png)

解决办法：点击网站，设置，将防跨站攻击关闭并保持，如下

![image-20210925155445084](https://img.kuizuo.cn/image-20210925155445084.png)

### 设置伪静态

接着再次访问网站会出现 404 页面不存在报错，在设置中找到伪静态，添加一个 thinkphp 的配置，如下

![image-20210925155705573](https://img.kuizuo.cn/image-20210925155705573.png)

再次访问后，出现的就是数据库配置的问题，配置一下数据库，导入数据，然后再次访问便可。

:::danger

再次提醒，生产环境下，请将`app_debug`设置为 false，不然非法用户可以通过人为试错，查询对应报错代码。

:::
