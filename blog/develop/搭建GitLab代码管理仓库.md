---
title: 搭建GitLab代码管理仓库
date: 2022-04-15
authors: kuizuo
tags: [git, gitlab]
---

![image-20220414235645607](https://img.kuizuo.cn/image-20220414235645607.png)

我只要有代码的项目，都会放到 Github 上，无论公开还是私有项目。一是相当于在云端备份了一份代码，二是可以很方便的分享给别人。但对于私有项目而言存放在别人那总归不好，而且Github 时常会出现无法访问的情况（即使搭了梯子）。所以就打算搭建一个私有的仓库，基于[GitLab](https://gitlab.com/)。

<!-- truncate -->

## 前提

一台服务器，系统 Linux，内存 >=4g

我的轻量应用服务器配置如下

![image-20220414210129510](https://img.kuizuo.cn/image-20220414210129510.png)

## 搭建

服务器我选择安装[宝塔面板](https://www.bt.cn/new/index.html)，对于个人项目，还是很推荐安装的，集成了一些软件商店，包括本次的主角，同时提供可视化页面操作，能省下很多敲命令的时间，~~同时也会增加忘记命令的记忆~~。

### 安装 GitLab

进入宝塔面板，点击软件商店，找到**GitLab 最新社区版**，点击安装

![image-20220414204808143](https://img.kuizuo.cn/image-20220414204808143.png)

实测等了 8 分钟，安装完毕即可查看 GitLab 的访问地址，账号密码。默认端口号 8099，记得在防火墙开放下该端口

![image-20220414213002293](https://img.kuizuo.cn/image-20220414213002293.png)

进入访问地址就可以看到 GitLab 的登录页面了。

### 修改密码

[Reset a user's password | GitLab](https://docs.gitlab.com/ee/security/reset_user_password.html#reset-the-root-password)

进入控制台（进入可能要稍等一段时间）

```sh
sudo gitlab-rails console
```

显示页面如下

```
[root@VM-4-5-centos ~]# sudo gitlab-rails console
--------------------------------------------------------------------------------
 Ruby:         ruby 2.7.5p203 (2021-11-24 revision f69aeb8314) [x86_64-linux]
 GitLab:       14.9.3 (ec11aba56f1) FOSS
 GitLab Shell: 13.24.0
 PostgreSQL:   12.7
------------------------------------------------------------[ booted in 29.71s ]
Loading production environment (Rails 6.1.4.6)
irb(main):001:0>
```

输入如下代码

```sh
u=User.find(1)
u.password='a12345678'
u.password_confirmation = 'a12345678'
u.save!
```

输出结果

```sh
irb(main):001:0> u=User.find(1)
=> #<User id:1 @root>
irb(main):002:0> u.password='a12345678'
=> "a12345678"
irb(main):003:0> u.password_confirmation = 'a12345678'
=> "a12345678"
irb(main):004:0> u.save!
=> true
irb(main):005:0>
```

最后输入`exit`退出控制台，然后输入下方代码重启 gitlab，密码就设置完毕了

```sh
gitlab-ctl restart
```

:::info

若重启或修改端口等操作后出现 502 错误，您可能需要等待 3-5 分钟才能正常访问 GitLab

:::

### 修改语言

点击右上角的头像=>Preferences 进入到设置，找到语言设置为简体中文，然后点击左小角的 Save changes。刷新网页语言就设置完毕了

![image-20220414215528543](https://img.kuizuo.cn/image-20220414215528543.png)

至于其他设置自行研究了。

## 创建项目

点击新建项目，这里就导入我的 blog 项目。

![image-20220414220221480](https://img.kuizuo.cn/image-20220414220221480.png)

选择 Github 后，会提示使用 GitHub 身份验证，这里需要拿到 Github 的[Token](https://github.com/settings/tokens)

![image-20220414220333437](https://img.kuizuo.cn/image-20220414220333437.png)

访问https://github.com/settings/tokens，新建一个Token，选择token有效期，以及相关权限（我这边选择全选，token不过期）

![image-20220414220507016](https://img.kuizuo.cn/image-20220414220507016.png)

![image-20220414220738714](https://img.kuizuo.cn/image-20220414220738714.png)

生成完毕后复制该 Token 到 GitLab 上，就可以看到该 Github 账号下的所有仓库了，这里我选择 blog 进行导入（导入需要一点时间）。

![image-20220414220858379](https://img.kuizuo.cn/image-20220414220858379.png)

导入完毕后与原仓库无特别区别

![image-20220414224639573](https://img.kuizuo.cn/image-20220414224639573.png)

### 自动同步项目

点击项目中设置=>仓库，找到镜像仓库。在 Git 仓库 URL 中填写格式如下

```js
// 原仓库git
https://github.com/kuizuo/blog
// 在https://后加上username@
https://kuizuo@github.com/kuizuo/blog
```

密码为上面的 Token（如果忘记的话，可以在 Github 的 Token 页中 Regenerate token），如下图所示

![image-20220414232028397](https://img.kuizuo.cn/image-20220414232028397.png)

------

基本上github能实现的操作gitlab也都能实现。

## 运行状态

放几张图

![image-20220414233435739](https://img.kuizuo.cn/image-20220414233435739.png)

输入 top 命令，按 M 按内存排序。

![image-20220414233416223](https://img.kuizuo.cn/image-20220414233416223.png)

对于内存压力还是蛮大的，毕竟安装的时候就要求 4g 内存以上。

## 总结

其实回到一开始的问题，既然Github有可能访问不了，为啥不要迁移到国内的[Gitee](https://gitee.com/)上。

~~除了瞎玩瞎折腾外~~，对于一些公司而言，他们不一定会使用这类开源的代码托管平台，而是自建一个像GitLab这样的代码仓库管理系统。此外别人的东西，多半都会有一定的限制，例如项目成员数量等等，所以才会有这次的尝试。

