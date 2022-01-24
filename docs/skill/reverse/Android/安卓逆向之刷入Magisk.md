---
title: APP逆向之刷入Magisk
date: 2021-12-09
tags: 
 - android
 - 刷机
---

<!-- truncate -->

> 相关链接: [小胡子的干货铺——Pixel 4 XL刷入Magisk、Root - 少数派 (sspai.com)](https://sspai.com/post/57923#!)

### **1.下载官方镜像包**

[Factory Images for Nexus and Pixel Devices  | Google Play services  | Google Developers](https://developers.google.com/android/images#coral)

在手机**设置**—**关于手机**—**版本号**查看自己手机系统的版本号**下载自己手机对应的版本！**，比如我这里的版本号是

**SP1A.210812.015** 

那么我就要在Version中找到对应的版本下载

![image-20211209142333912](https://img.kuizuo.cn/image-20211209142333912.png)

解压缩后，找到后缀为.zip的文件再解压缩，找到boot.img文件，将其单独复制出来。

### 2.下载Magisk Manager

这里我选择的是最新版的

[Releases · topjohnwu/Magisk (github.com)](https://github.com/topjohnwu/Magisk/releases)

![image-20211209150313229](https://img.kuizuo.cn/image-20211209150313229.png)

### 3.将复制文件置手机

将上述boot.img和MagiskManager-v7.4.0.apk两个文件传到手机里备用

### 4.安装Magisk

在手机上安装Magisk Manager后并打开，点击安装Magisk，**选择安装方法**—**选择并修补一个文件**，找到刚才传到手机中的boot.img并选中。

![image-20211209152217621](https://img.kuizuo.cn/image-20211209152217621.png)

这时会出现下方图二的修补过程，修补完成后**不要重启**。

![image-20211209152501019](https://img.kuizuo.cn/image-20211209152501019.png)

修补后会文件夹下生成一个**magisk_patched-23000_woltm.img**文件（每次生成的文件名都不一样）

上图框选的即为文件位置，**将该文件复制到platform-tools文件夹下**。

### 5.进入bootloader模式

关机后，同时长按**电源键**和**音量减键**，进入bootloader界面。（`adb reboot bootloader`）通过USB线将手机连接到电脑。

### 6.打开platform-tools文件夹，打开CMD窗口 输入下行命令

```
fastboot flash boot magisk_patched-23000_woltm.img
```

```
fastboot reboot
```

手机重启后，便成功刷入Magisk，并拥有Root权限。

![image-20211209153202961](https://img.kuizuo.cn/image-20211209153202961.png)
