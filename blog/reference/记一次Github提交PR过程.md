---
slug: github-pr-experience
title: 记一次Github提交PR过程
date: 2022-01-25
authors: kuizuo
tags: [随笔, github, blog]
keywords: [随笔, github, blog]
---

## 故事起因

博客正准备写一个项目展示的功能，其中 Docusaurus 中的[案例展示](https://docusaurus.io/zh-CN/showcase)就很适合改写成项目展示页面，然后无意间刷到我当时搭建博客所参考的博主[峰华](https://zxuqian.cn/)的博客也在展示页面。

![image-20220124214558772](https://img.kuizuo.cn/20220124214558.png)

于是脑海中就想：要不然提交一下我的博客试试看？然后便有了下文的故事

<!-- truncate -->

## 故事过程

当时具体提交的[Pull requests](https://github.com/facebook/docusaurus/pull/6458)

展示页面中有个很明显的按钮 Please add your site，点击后就跳转到 Github 的编辑页面了，不过浏览器不方便操作代码，所以我就 clone 了项目，根据提示，修改了两份代码（一个是添加背景图片，一个是添加博客的 json 数据）提交了 PR（Pull requests）。

![image-20220124215841410](https://img.kuizuo.cn/20220124215841.png)

一开始我是怀着尝试的态度去提交的，所以我不小心将代码格式化（也就是第 10 行 sortBy 两边的空格，原本代码风格是没有的），直到我已经提交上去的时候才发现 😂，甚至提交的时候我连 _description_ 都没写（所以我当时真是怀着尝试的态度去提交的）。虽然这是我第二次提交 PR，但也告诉我以后 commit 提交，一定一定一定要比对前后代码变动的地方，不然就会像上面这样。

提交完之后，很快就有机器人给我回复

![image-20220124220731250](https://img.kuizuo.cn/20220124220731.png)

大致的意思：首先很感谢你为社区提交请求，但是呢，为了合并你的代码，我们必须要贡献者签署我们的贡献者许可协议

很显然我并没有签署过，于是它就把解决方案也告诉了我，叫我访问https://code.facebook.com/cla，去签署CLA签名（贡献者许可协议），像下面这样，点击Submit就可以提交。

![image-20220124221203894](https://img.kuizuo.cn/20220124221203.png)

当时我看签署完毕后，返回 PR 页面还是提交要签署，所以我打算关掉这个 pr，准备重新提交一个新的 PR。（这种做法是真的愚蠢，尤其是在一个大型的开源项目）

就正当我关闭 pr 的时候，这时 Reviewers（审核人）给我回复了一条信息

![image-20220124221555614](https://img.kuizuo.cn/20220124221555.png)

> Hey, please don't close your PR if just because of the CLA. The bot will update your status soon after you signed it.

意思就是：请不要在签署 CLA 签名前关闭 PR，机器人会自动在你签署后自动为你更改状态

然后我就灰溜溜的重新开放 PR，那时候感觉我是真小白，太尴尬了 😅。

然后等待了差不多有半个小时左右，机器人给了回复

![image-20220124222432479](https://img.kuizuo.cn/20220124222432.png)

> Thank you for signing our Contributor License Agreement. We can now accept your code for this (and any) Meta Open Source project. Thanks!

意思：感谢您签署我们的贡献者许可协议。我们现在可以接受您的代码为这个(和任何)元开放源码项目。谢谢!

然后审核人为我的错误 commit 标题进行了修改~~docs: Add Kuizuo's Personal Website to showcase page~~ docs: add Kuizuo's Personal Website to showcase，**第一个单词 Add 不应该首字母大写**，不符合规范。

然后为我提交的代码做了一些小调整 minor tweaks，也就是上面所提到的 sortBy 空格，然后为我提供的展示图裁剪成标准尺寸。

![image-20220124222739483](https://img.kuizuo.cn/20220124222739.png)

审核人批准了我这两项修改，然后等待系统审核，具体审核的图我当时没截，现在没显示了，把已提交后的代码重新部署到 preview(预览)下，整个过程大约 5 分钟这样，接着审核人对我回复了一句 Great site, thanks! (很好的网站,谢谢)，然后这个 PR 状态就变成了 merged(合并)状态。

然后我犹豫了几分钟，不知道该怎么回复了，加上我英文表达不行，所以我原本中文是

谢谢,希望 Docusaurus 做的更好,一起努力 用软件翻译后 Thank you, Hope Docusaurus can do better. Let's go

![image-20220124222926032](https://img.kuizuo.cn/20220124222926.png)

虽然才过去两个小时，但是我现在回想起来都感觉贼丢人。

首先，我这个回复不是指定为他回复，而是相当于全体评论，贼不礼貌，然后这个蹩脚的英文翻译，我真像把 Let‘s go 改成 Let's work together，就算改了，感觉这个回复也太不礼貌了，这就已经不是英文表达能力，而是中文的表达能力了。

总之最后的结果是好的，我提交的 PR 已经成功合并到了 main 分支上，并且在下一个发布的版本中，案例展示中将会有我的博客显示在上面，现在访问[preview 网站](https://deploy-preview-6458--docusaurus-2.netlify.app/showcase/?name=kuizuo)，搜索 kuizuo 也能看到（B 格瞬间就上来了）

![image-20220124223506489](https://img.kuizuo.cn/20220124223506.png)

## 事后思考

整个过程下来，审核员给我的印象太好了，我这小白式的 PR，现在回看下来都感觉太丢人了。然后我一看审核员的[Github 账号](https://github.com/Josh-Cena)，好家伙，竟然是一名在中国上海的高中生！还是团队的核心人员！太牛了！

![image-20220124225625869](https://img.kuizuo.cn/20220124225625.png)

![image-20220124225830338](https://img.kuizuo.cn/20220124225830.png)

![image-20220124231207662](https://img.kuizuo.cn/20220124231207.png)

很难想象的到一位高中生竟能为默默的为开源项目做出贡献，而我的这次 PR 能提交成功，也与这位热心的国内学生有很大关系。（再次对我一开始报着尝试提交 PR 的态度表示抱歉）

但又回到我这边，这次提交 PR 的经过也让我学到了很多，commit 时一定要仔细对比更改前后的代码，提交的 commit 标题的规范，不必要的 closed，以及最重要的开源精神，让我看到一个实实在在开源者的样子，也是我梦寐以求的样子。

最后也祝 Docusaurus 能越做越好，也感谢这些默默为开源做出贡献的人们，正因为有你们世界才会变得更好。
