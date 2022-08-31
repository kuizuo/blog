---
id: look-up-port-and-kill-process
slug: /look-up-port-and-kill-process
title: 查看端口占用及结束进程
date: 2022-05-09
authors: kuizuo
tags: [system]
keywords: [system]
---

## Linux

### 查看端口占用情况

```sh
lsof -i:端口号
```

#### 实例

```sh
[root@VM-4-5-centos]# lsof -i:5002
COMMAND   PID USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
node    15196  www   25u  IPv6 63810147      0t0  TCP *:rfe (LISTEN)
```

更多 lsof 的命令如下：

```sh
lsof -i:8080：查看8080端口占用
lsof abc.txt：显示开启文件abc.txt的进程
lsof -c abc：显示abc进程现在打开的文件
lsof -c -p 1234：列出进程号为1234的进程所打开的文件
lsof -g gid：显示归属gid的进程情况
lsof +d /usr/local/：显示目录下被进程开启的文件
lsof +D /usr/local/：同上，但是会搜索目录下的目录，时间较长
lsof -d 4：显示使用fd为4的进程
lsof -i -U：显示所有打开的端口和UNIX domain文件
```

### netstat

**netstat -tunlp** 用于显示 tcp，udp 的端口和进程等相关情况。

netstat 查看端口占用语法格式：

```
netstat -tunlp | grep 端口号
```

- -t (tcp) 仅显示 tcp 相关选项
- -u (udp)仅显示 udp 相关选项
- -n 拒绝显示别名，能显示数字的全部转化为数字
- -l 仅列出在 Listen(监听)的服务状态
- -p 显示建立相关链接的程序名

### 结束进程

```sh
kill -9 PID
```

[Linux 查看端口占用情况 | 菜鸟教程 (runoob.com)](https://www.runoob.com/w3cnote/linux-check-port-usage.html)

## Windows

### 查看端口占用的 PID

```sh
netstat -ano | findstr "端口号"
```

例

```sh
  netstat -ano | findstr "8080"
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       18180
  TCP    192.168.123.210:14075  115.236.121.240:8080   ESTABLISHED     14060
  TCP    [::]:8080              [::]:0                 LISTENING       18180
```

### 查看指定 PID 的进程

如果想看占用进程，可以继续输入命令：

```sh
tasklist|findstr "PID"
```

例

```sh
tasklist|findstr "18180"
java.exe                     18180 Console                    1    852,996 K
```

### 结束进程

```sh
taskkill /T /F /PID PID
```

例

```sh
taskkill /T /F /PID 8080
```

强制（/F 参数）杀死 pid 为 8080 的所有进程包括子进程（/T 参数）
