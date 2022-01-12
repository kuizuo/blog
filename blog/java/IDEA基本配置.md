---
title: IDEA基本配置
date: 2022-01-06
authors: kuizuo
tags: [Jetbrains, idea, 工具]
---

准备系统的学习一遍 java（主要是后端与安卓），所以就免不了使用业界好评最高的 IDE 工具——IDEA。

同时在写这篇之前，JetBrains 全家桶就没怎么使用过，基本上我能用 vscode 我都用 codeRun 插件来运行，但对于一个大型项目，何况是开发 java 项目的话，vscode 有点难以胜任，加上后续会使用 GoLand，PyCharm 这些，所以很有必要记录下 JetBrains 全家桶的一些基本操作。

ps: 我本地电脑基本把大部分 JetBrains 产品给安装了一遍，而在去年 1 月 13 号淘宝上买的一个账号用于激活，到现在整整一年时间都没怎么使用 JetBrains 产品 😂

<!-- truncate -->

## 插件

### 主题图标

`Atom Material Icons` 设置文件图标

`Material Theme UI` 设置主题 (我一般设置 Atom One Dark Theme 这个主题)

`Rainbow Brackets` 彩虹括号

---

说实话，IDEA 内置集成了一堆好用的功能，比如 TODO，Git，这些在 VSCode 中插件的体验甚至有不如 IDEA。（尤其是这 Git 用过都说好），后续有其他插件才进行补充。

## 快捷键

[IntelliJ IDEA 常用快捷键 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/61690346)

### Ctrl

`Ctrl + D` 复制光标所在行 或 复制选择内容，并把复制内容插入光标位置下面

`Ctrl + W` 递进式选择代码块。可选中光标所在的单词或段落，连续按会在原有选中的基础上再扩展选中范围

`Ctrl + E` 显示最近打开的文件记录列表

`Ctrl + N` 根据输入的 名/类名 查找类文件

`Ctrl + G` 在当前文件跳转到指定行处

`Ctrl + F12` 弹出当前文件结构层，可以在弹出的层上直接输入，进行筛选

`Ctrl + 左键单击` 在打开的文件标题上，弹出该文件路径

### Alt

`Alt +1,2,3…9` 显示对应数值的选项卡，其中 1 是 Project 用得最多 （必备）

`Alt + Enter IntelliJ IDEA` 根据光标所在问题，提供快速修复选择，光标放在的位置不同提示的结果也不同

`Alt + Insert` 代码自动生成，如生成对象的 set / get 方法，构造函数，toString() 等

`Alt + 左方向键` 切换当前已打开的窗口中的子视图，比如 Debug 窗口中有 Output、Debugger 等子视图，用此快捷键就可以在子视图中切换

`Alt + 右方向键` 按切换当前已打开的窗口中的子视图，比如 Debug 窗口中有 Output、Debugger 等子视图，用此快捷键就可以在子视图中切换

`Alt + 前方向键` 当前光标跳转到当前文件的前一个方法名位置

`Alt + 后方向键` 当前光标跳转到当前文件的后一个方法名位置

### Ctrl + Alt

`Ctrl + Alt + L` 格式化代码，可以对当前文件和整个包目录使用

`Ctrl + Alt + O` 优化导入的类，可以对当前文件和整个包目录使用

`Ctrl + Alt + V` 快速引进变量

`Ctrl + Alt + S` 打开 IntelliJ IDEA 系统设置

`Ctrl + Alt + Enter` 光标所在行上空出一行，光标定位到新行

`Ctrl + Alt + 左方向键` 退回到上一个操作的地方

`Ctrl + Alt + 右方向键` 前进到上一个操作的地方

`Ctrl + Alt + 前方向键` 在查找模式下，跳到上个查找的文件

`Ctrl + Alt + 后方向键` 在查找模式下，跳到下个查找的文件

### Ctrl + Shift

`Ctrl + Shift + Z` 取消撤销

`Ctrl + Shift + W` 递进式取消选择代码块。可选中光标所在的单词或段落，连续按会在原有选中的基础上再扩展取消选中范围

`Ctrl + Shift + T` 对当前类生成单元测试类，如果已经存在的单元测试类则可以进行选择

`Ctrl + Shift + C` 复制当前文件磁盘路径到剪贴板

`Ctrl + Shift + V` 弹出缓存的最近拷贝的内容管理器弹出层

`Ctrl + Shift + E` 显示最近修改的文件列表的弹出层

`Ctrl + Shift + A` 查找动作 / 设置

`Ctrl + Shift + /` 代码块注释

`Ctrl + Shift + [` 选中从光标所在位置到它的顶部中括号位置

`Ctrl + Shift + ]` 选中从光标所在位置到它的底部中括号位置

`Ctrl + Shift + +` 展开所有代码

`Ctrl + Shift + -` 折叠所有代码

`F3` 选择下一个单词

`Ctrl + Shift + F7` 高亮显示所有该选中文本，按 Esc 高亮消失

`Ctrl + Shift + Space` 智能代码提示

`Ctrl + Shift + Enter` 自动结束代码，行末自动添加分号

`Ctrl + Shift +Backspace` 退回到上次修改的地方

`Ctrl + Shift + 左键单击` 把光标放在某个类变量上，按此快捷键可以直接定位到该类中

`Ctrl + Shift + 左方向键` 在代码文件上，光标跳转到当前单词 / 中文句的左侧开头位置，同时选中该单词 / 中文句

`Ctrl + Shift + 右方向键` 在代码文件上，光标跳转到当前单词 / 中文句的右侧开头位置，同时选中该单词 / 中文句

`Ctrl + Shift + 前方向键` 光标放在方法名上，将方法移动到上一个方法前面，调整方法排序

`Ctrl + Shift + 后方向键` 光标放在方法名上，将方法移动到下一个方法前面，调整方法排序

### Alt + Shift

`Alt + Shift + 前方向键` 移动光标所在行向上移动

`Alt + Shift + 后方向键` 移动光标所在行向下移动

### 调试

`Shift + F9` 调试模式运行

`F7` 步入，如果当前行断点是一个方法，则进入当前方法体内

`F8` 步过，如果当前行断点是一个方法，则不进入当前方法体内

`Shift + F8` 跳出步入的方法体外

`F9` 恢复程序运行，但是如果该断点下面代码还有断点则停在下一个断点上

### 自定义

在 vscode 中我通常都会设置光标键，比如

- `Shift + Alt + J`  左光标移动
- `Shift + Alt + K`  下光标移动
- `Shift + Alt + L`  右光标移动
- `Shift + Alt + I`  上光标移动
- `Shift + Alt + ;`  光标移动至行尾，相当于 End 键
- `Shift + Alt + H`  光标移动至行首，相当于 Home 键

同样的在 IDEA 肯定也要如此设置

在 setting 中找到 keymap，分别搜索关键字 up down left right home end 分别为其设置快捷键，如果遇到快捷键冲突，会提示 REMOVE（移除）还是 LEAVE（保留），选择 REMOVE（这些都是用处相对小的功能键，可以直接覆盖，介意者忽视）

还有一些快捷键针对 VSCode 我这就列举一下

- 重命名 `rename Shift+F6` ⇒ `F2`
- 重做 `Ctrl + Shift + Z` ⇒ `Ctrl + Y`
- 打开终端 `Alt + F12` ⇒ Ctrl + `（根据终端使用率）

如果习惯了 Vscode 快捷键方式也可以通过插件 VSCode Keymap 来对 IDEA 快捷键进行映射，相对使用成本会有所降低。

## 其他操作

### 快速生成代码

通过缩写或后缀的方式快速完成一些代码的补全，一般写完，按 tab 或回车即可。罗列一些比较常用的：

| 代码         | 效果                       |
| ------------ | -------------------------- |
| psvm         | 自动生成 main 函数         |
| .var         | 自动为对象生成声明         |
| sout / .sout | 输出：System.out.println() |
| .if          | 生成 if 判断               |
| .for         | 生成循环，默认是高级 for   |
| .try         | 生成 try … catch           |

可在 Settings ⇒ Editor ⇒ Live Templates 中 根据对应的语言生成相应的模板，也可自定义生成

![image-20220106052026798](https://img.kuizuo.cn/image-20220106052026798.png)

### 修改 Maven 依赖仓库位置

一般 Maven 所下载的依赖都会存储在`C:\User\{user}\.m2\repository` ，通过下图位置可以将其移动到其他地方。

![image-20220106052100190](https://img.kuizuo.cn/image-20220106052100190.png)
