---
title: vscode代码提示
date: 2020-09-14
tags:
 - vscode
 - 开发工具
---

<!-- truncate -->
## 教程

相信你在使用`vscode`中，肯定有过这样的问题，明明引入本地模块，但是有的时候就是没有对应的代码提示。如图

![image-20200901212906150](https://img.kuizuo.cn/image-20200901212906150.png)

像导入本地模块`fs`，却没有代码提示，想要有本地模块代码提示，最快捷的方法就是通过下面一行代码

```shell
npm install @types/node
```

但是如果你像上面那样，目录下没有`package.json`文件是肯定安装不上去的，这时候是需要初始化项目结构也就是执行下面的代码

```shell
npm init
或
npm init -y
```

然后在目录下你就能看到`node_modules`，在这个文件夹下有一个`@types`，这个目录就是存放你以后代码提示的目录，现在`@types`里面有`node`这个文件夹，也就是我们刚刚这个命令`npm install @types/node`后的node，现在试试看确实是有代码提示了，并且还有带星推荐。

![image-20200901214223439](https://img.kuizuo.cn/image-20200901214223439.png)

现在，我的代码里有`jquery`代码，但是本地已有`jquery.js`文件，又不想安装`jquery`的模块，但是又要`jquery`的代码提示，这时候你就可以输入下面代码，就能看到对应的代码。

```shell
npm install @types/jquery
```

![image-20200901214906038](https://img.kuizuo.cn/image-20200901214906038.png)

在比如有的库安装会没带代码提示，这时候就用上面的方法同样也可以有代码提示，例如`express`

`express`相关安装操作我就不赘述了，先看图片

![image-20200901215612611](https://img.kuizuo.cn/image-20200901215612611.png)

这app代码提示怎么全是js自带的代码提示。

然后在看`node_modules\@types`下，怎么只有我刚刚安装的那几个？

![image-20200901215826419](https://img.kuizuo.cn/image-20200901215826419.png)

不妨试试

```shell
npm install @types/express
```

这时候`node_modules\@types`下，就多了几个文件夹，其中一个名为express，那么现在代码提示肯定有了。

![image-20200901220225659](https://img.kuizuo.cn/image-20200901220225659.png)

果不其然，`vscode`里也有正常的代码提示了

![image-20200901220329481](https://img.kuizuo.cn/image-20200901220329481.png)

:::info

要注意的是，如果导入的库所采用的是TypeScript所书写的，那么就无需引用@types/xxx

:::

### 小结

从上面的例子中，可以得出`@types`这个文件夹里存放的都是`vscode`当前工作区的代码提示文件，想要对应的代码提示就直接`npm i @types/模块名`即可，如果你当前工作区没有代码提示，那么多半是这个问题。

### 自定义代码提示与快捷输入

这里补充一下，有时候我想自己定义一个代码提示，有没有办法呢，当然有，如果你恰巧学过java，想必每次写`System.out.println`都痛苦的要死，这时候你就可以像这样

1. 创建一个.vscode文件夹，在文件夹里创建一个名为`kuizuo.code-snippets`（只要后缀是code-snippets就行）
2. 在这个文件内写上如下代码

```json
{
	"System.out.println": {
      "scope": "java",
	  "prefix": "syso", 
	  "body": [ 
		"System.out.println($1);"
	  ],
	  "description": "输出至控制台，并带上换行符"
	},
}
```

- System.out.println为代码块的名字，无需强制。
- prefix：触发代码片段
- body：按下TAB后触发的内容填充，注意是一个数组类型，每行都需要用双引号修饰，不能使用模板字符串
- description：代码提示内容
- scope: 作用的语言，可多选，如"javascript,c"
- $+数字: 为光标的定位符，有多个则Tab跳转下个光标位置

上则代码的意思就是输入prefix内的`syso` 然后按下tab键就会把body内的`System.out.println($1);`代码提示显示出来，其中`$1`为光标位置，如图

![](https://img.kuizuo.cn/syso.gif)

但一般很少用到代码块，很多现成的插件就可以完全满足对应代码补全的需求，但有时候会方便很多。

像一些插件内会自带的代码提示，能不能“偷”过来使用一下呢，答案是肯定能的，这里我就已autoj -pro为例，(没了解过该软件可以忽视）

1. 首先安装autoJS_pro插件，然后进入C:\Users\Administrato\\.vscode\extensions\hyb1996.auto-js-pro-ext....  （Administrator为用户名）
2. 找到以snippets结尾的文件，打开全选复制其中的代码。
3. 打开vscode，如上操作，创建一个.vscode文件夹，后同
4. 把复制的代码段粘贴到我们创建的snippets文件，卸载auto.js-pro插件，重启即可
