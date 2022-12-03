---
slug: github-student-certification
title: 记 Github 学生认证
date: 2022-09-06
authors: kuizuo
tags: [随笔, github]
keywords: [随笔, github]
description: 记录本人 Github 学生认证艰辛过程与经验分享。
image: /img/blog/github-success.png
sticky: 1
---

![](https://img.kuizuo.cn/github_copilot_ready.jpg)

我个人是非常讨厌这些认证提交手续的，例如疫情健康报告，请假申请表等等，当然也包括这次 Github 学生认证。

这也就是我为什么迟迟不认证 Github 学生的原因，其实说白了就是没必要。但就在前段时间 [github copilot](https://github.com/features/copilot/ 'github copilot') 不是内测结束了，然后要开始收费了，收费标准 一个月 $10 / 一年 $100。这费用对于我本不富裕的生活雪上加霜。而 coplot 对教育认证有免费资格使用，于是乎就有了此次较为艰辛的 github 学生认证。

<!-- truncate -->

## 开始认证

介绍完故事背景后，就要开始认证了。

能看到这篇的估计也是想要学生认证的，这里就将我的认证过程总结出来。

### 1、不要科学上网

如果开启科学上网的话，提交时 github 会根据 ip 来判断所提交的学校位置和 ip 地址是否相近，如果差的很远的话是直接认证失败，并提示

> You appear not to be near any campus location for the school you have selected. If you are a distance learner then your school-provided academic affiliation documentation must state so.

大致意思：您没有出现在您所选择的学校的任何校园附近。如果你是远程学习者，那么你的学校提供的学术联系文件必须说明这一点。

也就是这一点，让我放弃我在老家认证学生认证的想法，而到开学才重新认证

但如果不开启科学上网就有可能获取不了 Google 地图与最终提交，我的做法是修改 host，然后需要 Google 地图的时候开启科学上网，然后获取定位信息后再关闭，最后提交的时候没开启科学上网。

### 2、学生认证资料

#### 教育邮箱

有的大学是没有教育邮箱的，就比如我的大学。但不用教育邮箱也是能认证成功的。（当然有的话反而更好通过）

#### 学生证

学生证学生卡这些都可以作为学生 ID 来认证的，不过在拍学生证之前一定要保证照片清晰，看情况决定时间水印，因为有可能会提示如下信息

> Your document does not appear to include a date demonstrating current academic affiliation. For countries utilizing non-standard calendars, you may need to capture the original document beside one with a converted date. You may include multiple documents in your image, so long as they are legible.

大致意思就是提交的资料没有当前时间认证，所以加个时间水印主要是为了这个。

但不过我有个同学是新号，5 月 github 注册的时候提示要他学生认证，然后他就随手拍了一下学生证的照片提交上去就认证通过了。据他回忆当时认证的信息填的很随意，然后第一次就通过了。而反倒是我提交了好多次学生证都失败了，怎么说呢，可能看账号吧。

#### 学信网在线验证报告

假设你拍照提交学生证一直失败（我就是这样），那么还可以通过 [学信网](https://account.chsi.com.cn/passport/login '学信网') 的学信档案 [申请教育部学籍在线验证报告](https://my.chsi.com.cn/archive/bab/xj/show.action '申请教育部学籍在线验证报告')

这个报告默认是中文的，但是 github 不一定认中文的，所以会拒绝。这时候就需要翻译成英文，但是在学信网申请英文在线报告需要额外 30 元，有效期 1 年。当然如果不想花这些钱，就想着是学生认证白嫖的话，也可以使用网页在线翻译，将内容翻译成英文，就得到了一份英文版的在线验证报告。而这个份报告是能通过的，我就是这样操作的。

每次提交的文件都要求不同，因为 github 后台会对文件做认证，所以就需要多拍照，多截图，做到图片相似，但不相同。

### 3、修改 github 个人信息

如果你按照上面的操作提交了，但还是不通过，并且只有下面一条提示信息的话

> You are significantly more likely to be verified if you have completed your [GitHub user profile](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-github-profile/customizing-your-profile/personalizing-your-profile 'GitHub user profile') with your full name and a short bio.

大致意思是，完善你的 github 个人账号信息（头像，昵称，简介），像我做的就是把昵称改成了我的真实姓名，简介就写我来自什么学校，热爱开源。就差最后大招把头像改成我的自拍照，背景是学校门口。当然 github 还算仁慈，最终还是没让我放出“大招”。

然后我修改了个人信息，并又提交了几次后，就终于成功了！

所以只出现了上面的一条提示，那么说明已经快要成功了，只不过 github 还要考核你的坚持程度，看你会不会放弃（我猜的）

## 我的认证过程

按照以上的步骤，我将演示一遍我的认证过程。

1、登录 [github education](https://education.github.com/benefits) ，选择学生那个按钮。

![image-20221010134753749](https://img.kuizuo.cn/image-20221010134753749.png)

2、首次表单填写邮箱，学校，以及使用Github的目的。**表单所提交内容全都要使用英文**

![image-20221010134942952](https://img.kuizuo.cn/image-20221010134942952.png)

3、再次填写一个表单，首先是照片证明，也就是学生认证资料。这里是使用的是**学信网的在线证明英文翻译**，Proof Type 选择 Other (Example: Screenshot of school portal)，备注内容填写证明来源，例如：**这份证明来自中国高等教育学生信息网（学信网），以下是在线证明地址。。。**

![image-20221010135500357](https://img.kuizuo.cn/image-20221010135500357.png)

其次第二个表单，根据你的学校信息填写即可。**切记到这一步的时候请不要使用科学上课，最好使用学校的网络来提交。**

![image-20221010135949606](https://img.kuizuo.cn/image-20221010135949606.png)

4、点击Process my application 提交，等待结果即可。

最终 Github 在今早发送邮箱告知我认证成功了！

![](https://img.kuizuo.cn/github_eduction_success.jpg)

只要你提供的学生信息真实有效，不断提交最终肯定是会成功的。在这认证期间我一共提交了 11 次请求。

![](https://img.kuizuo.cn/image_n3x8Cm8kMv.png)

期间收到的 Gtihub Education 邮箱信息如下：

![](https://img.kuizuo.cn/github_eduction_eamil.jpg)

最终也不负众望，在收到 github 通知的时候的，我就立马编写了这篇文章，记录了自己 github 学生认证的过程。

如果你有幸看到这篇文章，并想要认证 github 学生资格，希望这篇文章有帮到你。

## 感谢

最终也是要感谢 Github 为广大开发者提供平台，让一群志同道合的人在上面分享并创造想法，同时也感谢这些默默为开源做出贡献的前人，不断为这个世界增添一丝色彩。
