---
title: Charles与postern抓包
date: 2020-02-02
tags:
 - 抓包
 - app
---

## 前言

关于刷机实在有太多坑了，这里我的手机是谷歌的Pixel，刷安卓8.1系统，有关刷机的文章 

[ 一篇文章彻底搞定安卓刷机与ROOT](https://mp.weixin.qq.com/s?__biz=MzUxMzEwODAxOA==&mid=100000054&idx=1&sn=b2c18b50f99574b1849a5f695e1651fa&chksm=795b706b4e2cf97d7353ec2fc349026be3da209632f6ffbc2312cde8027e6965e98a125e44d6&mpshare=1&scene=23&srcid=0202Ney3ClZ4kcLYaLZlSHuZ&sharer_sharetime=1612221278527&sharer_shareid=0bc6bee5ebc1a090cf5e0554bcceba2e#rd)

[Edxposed安装](https://mp.weixin.qq.com/s?__biz=MzUxMzEwODAxOA==&mid=100000208&idx=1&sn=aac5bb0686bf195a1e68f05b5789930e&chksm=795b708d4e2cf99b12bd26f4ba30f72cfa9cfa7cdd2a3fdf31793618b3aac048bb9d3c3f3fe6&mpshare=1&scene=23&srcid=0202NDHQyyYwxvdCJirkQdb7&sharer_sharetime=1612269939629&sharer_shareid=0bc6bee5ebc1a090cf5e0554bcceba2e#rd)

非配置fd代理，而是使用Charles（吾爱破解有）与postern https://github.com/postern-overwal/postern-stuff/blob/master/Postern-3.1.2.apk

补: 修改根路径下的default.prop文件，将ro.debuggable=0改成1，即可调试模式 

### Charles配置

#### 1、菜单 -> Proxy -> Proxy Setting… 如图

![image-20210202045815609](https://img.kuizuo.cn/image-20210202045815609.png)

用Charles针对抓安卓的包，所以在Windows下就不设置代理。同时使用Socket代理 而不是http代理，配置端口（这里为8999）即可

### 2、Denying access from address not on ACL

要在charles允许设备，需要如下设置

![image-20210517020819625](https://img.kuizuo.cn/image-20210517020819625.png)

然后添加一个0.0.0.0/0的ip  即可抓取所有设备

![image-20210517020904361](https://img.kuizuo.cn/image-20210517020904361.png)



### Postern配置

#### 1、安装postern

#### 2、配置代理 如图

![image-20210202050134094](https://img.kuizuo.cn/image-20210202050134094.png)

 用户名与密码加密类型可不填

注： 有个小坑，要保证电脑与手机连接的是同一个Wifi网络，点击 菜单 -> Help -> Local IP 可查看当前网络下IP 如图，一般为Wireless（笔记本），具体都要尝试一遍

![image-20210202050422857](https://img.kuizuo.cn/image-20210202050422857.png)

#### 3、配置规则 如图

![image-20210202050513312](https://img.kuizuo.cn/image-20210202050513312.png)



这里也要注意，在**第一次**配置的时候，点击保存后，Charles会弹出对话框，点击右边Allow即可，如果没有出现，那么多半是代理IP没有配置好，这时候尝试多开关几次VPN与设置Local IP中的IP即可。

![image-20210202051719212](https://img.kuizuo.cn/image-20210202051719212.png)

### 配置SSL证书

此时可以抓包，但抓取HTTPS则是unknown，即未解密的，这时候就要配置SSL证书

#### 1、打开菜单 

#### 菜单栏  Proxy -> SSL Proxying Settings 

![image-20210202051138064](https://img.kuizuo.cn/image-20210202051138064.png)

在左侧添加一个 * 表示匹配所有请求，点击OK。这时还没完，代理抓包肯定要配置证书的（FD就是如此），点击下图位置

![image-20210202051440984](https://img.kuizuo.cn/image-20210202051440984.png)

弹出安装提示，并非直接安装

![image-20210202051610186](https://img.kuizuo.cn/image-20210202051610186.png)

访问 chls.pro/ssl 下载 安装(与fd类似)

但要注意，在Socket代理下 可能无法下载证书，这时候	切换至HTTPS代理（同FD配置），然后下载证书安装，设置下锁屏等等，即可

还有 不同的电脑设备都需要重新安装一下证书才可

### 2、电脑端也要安装证书，如图

![image-20210517023044653](https://img.kuizuo.cn/image-20210517023044653.png)

点击 然后下一步即可

### 检测证书

由于fd与charles都是替换证书的，安装的证书都是用户下的，而非系统下（7.0以上），一些app会检测证书，从而无法发送请求，这时候就需要将用户证书移动到系统证书下

系统证书路径    `/etc/security/cacerts`

用户证书路径    `/data/misc/user/0/cacerts-added`

命令

```sh
#挂载为可读写 将根路径挂载为可读写
mount -o rw,remount /

# 将当前目录下所有文件移动置系统证书路径下
cp * /etc/security/cacerts
```

不执行 `mount -o rw,remount /` 则会报 cp: /etc/security/cacerts/03f1f1d0.0: Read-only file system

或用Root Explorer 将用户证书移动到系统证书路径下即可

补：当时我是无法挂载可读写的，但是root权限有提示，可以adb shell 与 su 但就是无效root，于是只好重刷机一遍，最终才解决的。

### 大功告成

这时候就可以正常的抓到安卓对应的包了。

## 对比FD配置代理 与 Charles和Postern组合

首先配置代理属于会话层，很容易获取到代理的ip与端口，检测到是否代理，从而限制app使用，

而挂了VPN则是将在网络层中，不易被检测，同时能获取到应用层（HTTP）与传输层（TCP）等数据。

同时FD需要来回配置代理特别麻烦，而Postern只需要开启VPN与关闭即可。所以在wifi中就无需配置代理。
