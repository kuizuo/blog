---
id: solution-of-bootloader-lock
slug: /solution-of-bootloader-lock
title: 解Bootloader锁
date: 2021-12-09
authors: kuizuo
tags: [android, bootloader, 刷机]
keywords: [android, bootloader, 刷机]
---

<!-- truncate -->

最近准备重学安卓逆向与开发，自然工具是肯定少不了，最为重要的便是手机。之前的手机是 Pixel，但是手机性能不太好，使用起来一卡一卡的（程序安装的有点多）。于是就准备换台 Pixel 4XL 欧版的来作为新设备。

于是便记录下手机的配置逆向环境的过程，而这篇就是刷机最主要的一步，解 bl 锁，不然就没有后续刷面具，root 等等操作了。

相关文章 [小胡子的干货铺——Pixel 4 XL 解锁 Bootloader - 少数派 (sspai.com)](https://sspai.com/post/57922)

## 开始解锁

:::danger

**前文提示：解锁后，手机上所有数据将被清除重置，请备份重要数据!**

:::

### 下载工具包

**需要科学上网才能下载**

1、platform-tools.zip: （解压到一个文件夹下）

https://developer.android.com/studio/releases/platform-tools.html

2、USB 驱动.zip:（放同文件夹不需要解压）

https://developer.android.com/studio/run/oem-usb.html#InstallingDriver

### OEM 解锁

1、**设置**—**关于手机**—**版本号**连按七下

2、返回上一级（**设置**）—**系统**—**高级**—**开发者选项**—打开“**OEM 解锁**”，后续按提示操作

3、**开发者选项**—打开“**USB 调试**”（备用）

### 更新驱动

1、电脑开始菜单旁边搜索“**设备管理器**”并打开

2、通过 USB 线将手机连接到电脑

3、找到新出现的设备就是你的手机，右击更新驱动—自动搜索更新驱动或者手动在桌面搜索刚才下载的驱动并安装

![img](https://img.kuizuo.cn/f49f1e5afc077dafab5d74a72965f8ba.png)

如下图提示则说明安装成，接着就要开始解锁了

![image-20211209133458792](https://img.kuizuo.cn/image-20211209133458792.png)

### Bootloader 解锁

1、**关机**后，同时按住**电源键**和**音量减键**，进入 Bootloader 界面。

![image-20211209135203559](https://img.kuizuo.cn/image-20211209135203559.png)

可以看到**Device-State: locked** 表明为加锁状态

2、通过 USB 线将手机连接到电脑。

3、打开桌面 platform-tools 文件夹，在当前文件夹下打开 CMD 窗口（不可打开 PowerShell，不然命令不可用）

4、键入以下命令检查 fastboot 连接：

```sh
fastboot devices
```

回车后应该显示你的设备序列号，如果不是，你需要确保你的驱动程序已正确安装。

5、确认 fastboot 连接没问题，即可运行解锁 bootloader 命令：

```sh
fastboot flashing unlock
```

你现在应该在手机上看到一个操作界面，要求你确认此操作。使用音量键选择（按一下音量键下即可），使用电源键确认（选择 Unlock the bootloader 并确认）。确认该过程完成，然后键入此命令：

```sh
fastboot reboot
```

手机重启，完成解锁。此时手机界面就会显示 Google 解锁的提示动画。

**解锁后，手机上所有数据被清除重置，如需执行后续工作，须重新开启开发者选项、USB 调试**

## 解除 WiFi 网络受限

由于国内网络访问谷歌服务器会被墙，导致 wifi 网络受限。通过下面操作可以解除 WiFi 网络受限

1、手机开机状态下，通过 USB 线将手机连接到电脑。

2、打开桌面 platform-tools 文件夹，打开 CMD 窗口

3、输入命令

```
adb shell settings put global captive_portal_https_url https://www.google.cn/generate_204
```

4、打开飞行模式再关闭，查看是否已解除受限。
