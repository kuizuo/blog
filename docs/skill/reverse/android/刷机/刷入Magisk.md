---
id: brush-magisk
slug: /brush-magisk
title: 刷入Magisk
date: 2021-12-09
authors: kuizuo
tags: [android, magisk, 刷机]
keywords: [android, magisk, 刷机]
---

<!-- truncate -->

> 相关链接: [小胡子的干货铺——Pixel 4 XL 刷入 Magisk、Root - 少数派 (sspai.com)](https://sspai.com/post/57923#!)

### **1.下载官方镜像包**

[Factory Images for Nexus and Pixel Devices | Google Play services | Google Developers](https://developers.google.com/android/images#coral)

在手机**设置**—**关于手机**—**版本号**查看自己手机系统的版本号**下载自己手机对应的版本！**，比如我这里的版本号是

**SP1A.210812.015**

那么我就要在 Version 中找到对应的版本下载

![image-20211209142333912](https://img.kuizuo.cn/image-20211209142333912.png)

解压缩后，找到后缀为.zip 的文件再解压缩，找到 boot.img 文件，将其单独复制出来。

### 2.下载 Magisk Manager

这里我选择的是最新版的

[Releases · topjohnwu/Magisk (github.com)](https://github.com/topjohnwu/Magisk/releases)

![image-20211209150313229](https://img.kuizuo.cn/image-20211209150313229.png)

### 3.将复制文件置手机

将上述 boot.img 和 MagiskManager-v7.4.0.apk 两个文件传到手机里备用

### 4.安装 Magisk

在手机上安装 Magisk Manager 后并打开，点击安装 Magisk，**选择安装方法**—**选择并修补一个文件**，找到刚才传到手机中的 boot.img 并选中。

![image-20211209152217621](https://img.kuizuo.cn/image-20211209152217621.png)

这时会出现下方图二的修补过程，修补完成后**不要重启**。

![image-20211209152501019](https://img.kuizuo.cn/image-20211209152501019.png)

修补后会文件夹下生成一个**magisk_patched-23000_woltm.img**文件（每次生成的文件名都不一样）

上图框选的即为文件位置，**将该文件复制到 platform-tools 文件夹下**。

### 5.进入 bootloader 模式

关机后，同时长按**电源键**和**音量减键**，进入 bootloader 界面。（`adb reboot bootloader`）通过 USB 线将手机连接到电脑。

### 6.打开 platform-tools 文件夹，打开 CMD 窗口 输入下行命令

```
fastboot flash boot magisk_patched-23000_woltm.img
```

```
fastboot reboot
```

手机重启后，便成功刷入 Magisk，并拥有 Root 权限。

![image-20211209153202961](https://img.kuizuo.cn/image-20211209153202961.png)
