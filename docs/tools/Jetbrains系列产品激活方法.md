---
id: jetbrains-product-activation-method
slug: /jetbrains-product-activation-method
title: Jetbrains系列产品激活方法
date: 2020-09-03
authors: kuizuo
tags: [Jetbrains, 工具]
keywords: [Jetbrains, 工具]
---

![jetbrains](https://img.kuizuo.cn/jetbrains.jpg)

<!-- truncate -->

## 前言

> 参考链接 [知了](https://zhile.io/2018/08/25/jetbrains-license-server-crack.html)

无论你是什么开发者，多多少少肯定听过`Jetbrains`，或者肯定见过相关类似界面，如果真不知道问问百度。官网 [点我去下载](https://www.jetbrains.com/zh-cn)。

**本文内容只用于学习，请勿用于商务用途，请支持正版！**

## 开始激活

需要说下 Jetbrains 产品的两种外面主流激活方式

- 激活码激活（一般没隔半年就要重新百度新的激活码，非常不推荐）
- `jetbrains-agent`补丁（使用期到 2089 年，但有局限，本文着重举这个方法）
- 去购买账号 20 元一年（本人已用该方法，不贵且方便（支持所有 Jetbrains 产品激活），推荐）

### 下载激活工具

首先，请下载`jetbrains-agent-latest.zip`工具 [点我下载](https://wwe.lanzous.com/i3UTYjdd0mh) 解压会看到两个文件 一个`jetbrains-agent-latest.zip`不用再解压另一个安装参数（后面会用到）

我用这个激活工具实现`PyCharm`和`WebStorm`还有`IDEA`的激活，其余类似产品的激活方式都一样。

**重点来了！这种激活是有前提的**

1. **软件不要更新! 尽可能用旧版本**

   尽管这个补丁是 2020 年 4 月 10 日的，但有可能软件更新后会用不了，所以要破解请不要更新或安装最新版（本文 9 月 8 号已测试没问题），毕竟人家软件商又不傻，能让你白嫖免费用最新的，如图下载其他版本。

![image-20200903064643648](https://img.kuizuo.cn/image-20200903064643648.png)

2. **清除 hosts 文件内有关 jetbrains**

   如果你在之前就接触过这类软件的激活使用，那么有可能别人的文章是让你这么做的

   添加一行`0.0.0.0 account.jetbrains.com`到`C:\Windows\System32\drivers\etc\hosts`文件中

   而现在，请把上面那一行删掉，没必要，甚至你都有可能都访问不了 jetbrains 官网

### 运行要激活的软件

1. 首先运行软件（这里以 IDEA2019.3 为例），如果是第一次的话会进行一些正常配置然后弹出一个如下注册框，勾选 Evaluate for free, 点击 Evaluate:

![wps1](https://img.kuizuo.cn/wps1.jpg)

​ 正常进入到工具编程开始界面，进入第二步

2. 用鼠标拖动下载完的激活工具`jetbrains-agent-latest.zip`文件到 到编程界面,或者一开始创建项目页面

   ![image-20200903070702901](https://img.kuizuo.cn/image-20200903070702901.png)

   提示选择 Restart 重启软件，这里就不放图了。

3. 重新打开 idea，激活方式默认`Activation code`，啥也别改 直接点击为 IDEA 安装即可

![image-20200903070849707](https://img.kuizuo.cn/image-20200903070849707.png)

​ 补充一下，如果你是用我提供给你的补丁的话，可能会遇到如下图

![image-20200908111018549](https://img.kuizuo.cn/image-20200908111018549.png)

​ 有个安装参数，你把下面的文本复制粘贴到输入框即可

```
LFq51qqupnaiTNn39w6zATiOTxZI2JYuRJEBlzmUDv4zeeNlXhMgJZVb0q5QkLr+CIUrSuNB7ucifrGXawLB4qswPOXYG7+ItDNUR/9UkLTUWlnHLX07hnR1USOrWIjTmbytcIKEdaI6x0RskyotuItj84xxoSBP/iRBW2EHpOc
```

接着提示安装 jetbrains-agent 成功.... 选择是就对了。

4. 稍等片刻，这时候点击 Help->About 查看到期时间 2089 年

![image-20200903071235404](https://img.kuizuo.cn/image-20200903071235404.png)

没错现在 IDEA 已经成功激活破解了，这时候再点 Help->Register 查看注册情况

![image-20200903071428877](https://img.kuizuo.cn/image-20200903071428877.png)

就此 IDEA2019.3 已成功激活破解。就是这么简单。

### 补充几点

现在你已能成功破解 Jetbrains 相关的软件，但我还需要补充几点

首先在 Help->Edit Custom VM Options 中，你可以看到`-javaagent:C:\Users\Public\.jetbrains\jetbrains-agent-v3.2.0.de72.619`这个字样

![image-20200903071942873](https://img.kuizuo.cn/image-20200903071942873.png)

也就是这个，决定了你能否运行 IDEA 的关键，现在我找到对应的目录下，把这两个文件先移走，然后重新运行 IDEA，你就会发现运行不了，同样的你若删除了这一行也是运行不了的。反正闲着没事就别管这些地方，甚至你都不用修改软件对应`bin`下的以`.exe.vmoptions`后缀文件里的内容。

![image-20200903072112685](https://img.kuizuo.cn/image-20200903072112685.png)

为什么要说这个呢，因为你到时候如果是要用其他的补丁，可能要你更改的就是上面那文件的对应路径或者 bin 下对应的两个文件，你到时候根据对应的使用方式修改就行，并不难。

第二点，也是最坑的一点！

你在执行完第三步的时候，重启后，发现还在`License Activation`激活界面，先不管，在点击试用，然后点开 Help->About 发现显示到期时间不是 2089 年，再点 Help->Register 查看注册情况，发现在`Activation code`中并没有内容，然后尝试把激活工具里的`Activation code.txt`里的激活码复制到上面，然后就出现如下图的情况

![image-20200903073459886](https://img.kuizuo.cn/image-20200903073459886.png)

~~这里我就用 Go 来做演示了，卸载重装够折腾的了~~，<font color='#ff0000'>Key is invalid.</font>啥玩意?

正常你按我上述的步骤是不会出现这的，而出现这种情况有两种原因

1. 你的 agent 是真的没有配置好，请把上述步骤重新做一遍，然而一般不会是这个问题。

2. 软件是最新版的，我上面说到，软件不宜最新，破解补丁和版本不匹配，就会遇到这种情况。

   这时候的解决办法

   1. 找最最新的破解补丁 （我提供给你的已经是最新的了，就没必须要在折腾了，像上面的 go 语言也是能成功破解不会出现`Key is invalid`的）
   2. 使用较旧版本 （直接官网就旧版本下载即可）
   3. **购买激活码或账号（有钱，任性）**，个人建议直接去淘宝购买一个账号 20 元一年，主要使用插件激活是真的折腾，账号联网激活，是可以激活最新版的但要注意的是，你需要把我上面所说的 Help->Edit Custom VM Options 将`-javaagent:C:\Users\Public\.jetbrains\jetbrains-agent-v3.2.0.de72.619` 注释掉

## 总结

最后要说一句，环境配置这些说实在话挺折腾人的，在我学习阶段中，在这些配置中就花费了大量的时间。从环境变量，到下载各种开发工具，安装各种插件，各种包，库等等，有的还需要破解。这期间每一次都至少来回反复了 4,5 遍，都经历过几天折磨，安装卸载重启都成了家常便饭了，但这又是学习中必不可少的一个阶段。同时每次成功配置完，那种感觉真的只有经历过的人才会知道，也驱使我不断前进。

有时候可能都忘记之前这个环境是怎么安装使用的，想更新一下软件，又怕花费太多时间，甚至在我写这篇文章的时候，我都快忘记我之前是怎么破解的(然而我离我最近一次破解也不过一个月左右)，然后又百度相关了各种破解，同时也算是搞懂了`key is invalid.`这个问题和解决方式，也同时记录一下。
