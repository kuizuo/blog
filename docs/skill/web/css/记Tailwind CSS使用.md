---
id: tailwind-css-usage
slug: /tailwind-css-usage
title: 记Tailwind CSS使用
date: 2022-11-11
authors: kuizuo
tags: [css, tailind]
keywords: [css, tailind]
---

最近把之前写的一个Web项目的页面给重构了一下，使用上了[Tailwind CSS](https://www.tailwindcss.cn/)，虽然之前就使用过，但是没有记录下来，这次就相当于对该技术栈进行一次总结。

<!-- truncate -->

## 介绍

借用官方描述

> Tailwind CSS 是一个功能类优先的 CSS 框架，它集成了诸如 `flex`, `pt-4`, `text-center` 和 `rotate-90` 这样的的类，它们能直接在脚本标记语言中组合起来，构建出任何设计。

## Tailwind CSS组件库

- [Headless UI](https://headlessui.dev/)

- [Flowbite](https://flowbite.com/)

- [Tailwind Elements ](https://tailwind-elements.com/)

官方组件库要钱就没写了，以上资源均来自 [awesome-tailwindcss](https://github.com/aniftyco/awesome-tailwindcss)

## WindiCSS

Tailwind CSS可能有些缺点，例如构建速度慢，不支持任意值，不支持[属性化模式](https://cn.windicss.org/features/attributify.html)等等。如果恰好在Vue项目的话，倒是推荐使用Windi CSS，并且它完美兼容Tailwind CSS，同时新增了许多额外特性，进一步提升编码体验，同时Windi CSS对Vite有很好的集成，具体可在 [官网特性](https://cn.windicss.org/features/#features) 中查看，这里列举几些。

### 指令

使用@apply，将一系列的原子类封装成一个类下。如下

```css
.btn {
  @apply font-bold py-2 px-4 rounded;
}
```

更多可查看 [函数与指令](https://www.tailwindcss.cn/docs/functions-and-directives)

### 可变修饰组

```
<div class="hover:(bg-gray-400 font-medium) bg-white font-light"/>
```

可以将一串hover前缀的原子类，封装在括号内。

### 自动值推导

在windicss中有这样的特性，可以允许自定义size，而不想tailwindcss中以整数方式，如`p-2.5`对应`padding: 0.625rem;` 这在windicss是被支持的。

同时还可以指定size的变量，如`p-4px`对应`padding: 4px;`，同样对于分数形式的比例也同样是支持的。

甚至可以传递css变量的名称，如

```
bg-${variableName}
```

将转化为

```
background-color: var(variableName);
```

:::info

补充: 在Tailwind CSS 3.0中，支持`bg-[#bada55]`或`h-[24px]`的形式，即自定义样式，方括号内为具体变量值。

:::

### 属性化模式

对于一长串的class字符串，在维护的时候寻找其中的原子类特别不方便，使用属性化模式就可以写成下面这种形式

```html
<button 
  bg="blue-400 hover:blue-500 dark:blue-500 dark:hover:blue-600"
  text="sm white"
  font="mono light"
  p="y-2 x-4"
  border="2 rounded blue-200"
>
  Button
</button>
```

### 暗色模式

#### class模式（常用）

首先在tailwind.config.js中，将darkMode设置为class。

```javascript
export default {
  darkMode: 'class',
  // ...
}
```

它将会侦测父元素的 `class="dark"`，通常你可以将它放置在 `html` 元素上面，这样就可以全局生效了。

```html
<!-- Dark mode not enabled -->
<html>
<body>
  <!-- Will be white -->
  <div class="bg-white dark:bg-black">
    <!-- ... -->
  </div>
</body>
</html>

<!-- Dark mode enabled -->
<html class="dark">
<body>
  <!-- Will be black -->
  <div class="bg-white dark:bg-black">
    <!-- ... -->
  </div>
</body>
</html>
```

然后需要定义一个按钮，用于切换暗色与亮色模式（即给html标签添加dark类）。

**原子类前加上dark:则表示在暗色模式下的背景色**。此外，像hover，focus这些也是同理的。

#### 媒体查询模式

它使用了浏览器内置的 `@media (prefers-color-scheme: dark)` 查询，总是会与用户的系统表现相匹配。也就是根据你系统所处的环境而更换，不需用户手动点击切换按钮切换。不做例子演示（因为没用过）



## 前置知识

在写相关原子类，需要补充写前端单位的换算

### 单位换算

| 单位 | 转换                                                         |
| ---- | ------------------------------------------------------------ |
| px   | 1屏幕实际像素                                                |
| rpx  | 微信小程序中的单位 规定屏幕实际宽度 = 350rpx                 |
| em   | 1em = 当前元素font-size大小(px) 如果当前font-size大小是em单位 则继承父级 如果没有父级 则取浏览器默认值 |
| rem  | 1rem = 根元素 font-size大小(px) 如果根元素font-size的大小是rem单位 则取浏览器默认值 |
| pt   | 1pt = DPI/72; (px)                                           |
| vw   | 1vw = 1% * 页面实际宽度（px）                                |
| vh   | 1vh = 1% * 页面实际高度（px）                                |
| vmax | 1vmax = 1vh > 1vw ？ 1vh ：1vw                               |
| vmin | 1vmin = 1vh < 1vw ？ 1vh ：1vw                               |
| ch   | 1ch = 当前元素font-size大小 的 0 的宽度(px) 如果没有继承父级 直到浏览器默认值 |

通常来说桌面浏览器默认字体大小是16px，而1rem对于的也就是16px。要注意的是根元素，即html{font-size:16px;}。对于不同设备（桌面端，移动端）font-size不一定都是16px，所以为了适配使用，就需要按照一定的比例进行换算。

而在tailwind css中 **大部分**原子类对于的属性单位都是以rem。其中换算比例为1: 0.25rem，举个例子。m-1对应的是 margin: 0.25rem，m-4对应margin: 1rem，即16px。

其中这里的1与4对应的是{size}，**记住4size对应1rem即可**。

### 响应式设计

一个网站没有响应式是没有灵魂的，在Tailwind中内置了几个常用设备分辨率的方案。即5个断点。（注意，这里使用的的是min-width）

| 断点前缀screen | 最小宽度 | CSS                                  |
| -------------- | -------- | ------------------------------------ |
| `sm`           | 640px    | `@media (min-width: 640px) { ... }`  |
| `md`           | 768px    | `@media (min-width: 768px) { ... }`  |
| `lg`           | 1024px   | `@media (min-width: 1024px) { ... }` |
| `xl`           | 1280px   | `@media (min-width: 1280px) { ... }` |
| `2xl`          | 1536px   | `@media (min-width: 1536px) { ... }` |

通常用法  **{screen}:原子类** ，当页面最小宽度处于该宽度，则会启动对于原子类样式。因为使用的是min-width，通常来说先为移动设备设计布局，接着在 `sm` 屏幕上进行更改，然后是 `md` 屏幕，以此类推。

**不要使用 `sm:` 来定位移动设备**

```html
<!-- This will only center text on screens 640px and wider, not on small screens -->
<div class="sm:text-center"></div>
```

**使用无前缀的功能类来定位移动设备，并在较大的断点处覆盖它们**

```html
<!-- This will center text on mobile, and left align it on screens 640px and wider -->
<div class="text-center sm:text-left"></div>
```

不过如果使用windicss的话，还支持`<`与`@`前缀，前者对于的是max-width，后者则是在min-width与max-width两者之间。会比tailwind好用的多。具体可查 [响应式设计 | Windi CSS](https://cn.windicss.org/features/responsive-design.html#breakpoints)



## 原子类

### 内外边距

语法

```
p{t|r|b|l|x|y}-{size}
```

**内边距padding缩写为p，margin缩写为m。**

**top对应t，right对应r，bottom对应b，l对于left。x对于left和right，y对应top与bottom**

记住上面几则规则，大部分的css原子类都 能写的出来。然后在此基础上，在添加size即可。

如果想要给size设置为负值，直接在原子类前面加上`-`号即可，如`-p-1`（windicss中，要么就在配置文件中增加[外边距 负值](https://www.tailwindcss.cn/docs/margin#-8)）

#### 间隔

```
space-{x|y}-{size}
```

为子元素添加下列css元素。

```
--tw-space-x-reverse: 1; 
margin-right: calc(0.125rem * var(--tw-space-x-reverse)); 
margin-left: calc(0.125rem * calc(1 - var(--tw-space-x-reverse)));
```

### 宽高

宽高的相关原子类语法与边距相似，但补充了一些比例形式的类。

可以使用 `w-{fraction}` 或 `w-full` 将元素设置为基于百分比的宽度，例如w-1/2 为 width: 50%; w-full则是width: 100%，具体可在官网中查看。还有以下几种不那么常用。

| Class    | Properties          |
| -------- | ------------------- |
| w-screen | width: 100vw;       |
| w-min    | width: min-content; |
| w-max    | width: max-content; |

#### 最大最小宽高

语法

```
{min|max}-{w|h}-{size}
```

### 字体

#### 样式

- font-sans 

- font-serif

- font-mono

我个人倾向使用mono

#### 大小

字体大小不同于边距与宽高，size对应响应式的，如`xs sm base lg xl 2~9xl`，同时语法规则为`text-{size}`。

:::info

这里的text主要针对是文本操作，很容易记混成`font-{size}`。

:::

#### 粗细（字重）

字体粗细有如下几种，通常来说使用较多的是`font-semibold`（默认为normal，即400）

| Class           | Properties        |
| --------------- | ----------------- |
| font-thin       | font-weight: 100; |
| font-extralight | font-weight: 200; |
| font-light      | font-weight: 300; |
| font-normal     | font-weight: 400; |
| font-medium     | font-weight: 500; |
| font-semibold   | font-weight: 600; |
| font-bold       | font-weight: 700; |
| font-extrabold  | font-weight: 800; |
| font-black      | font-weight: 900; |

#### 行高

语法

```
leading-{size}
```

此外还有

| Class           | Properties          |
| --------------- | ------------------- |
| leading-none    | line-height: 1;     |
| leading-tight   | line-height: 1.25;  |
| leading-snug    | line-height: 1.375; |
| leading-normal  | line-height: 1.5;   |
| leading-relaxed | line-height: 1.625; |
| leading-loose   | line-height: 2;     |

其中`line-height: 1;`根据**该元素本身的字体大小**设置行高，如该元素字体是16px，line-height:1; 的行高就是16px;

### 文本

#### 颜色

[自定义颜色 - Tailwind CSS 中文文档](https://www.tailwindcss.cn/docs/customizing-colors)

在tailwind中颜色通常按50，100~900分级。定义颜色{colors}的语法为

```
{color}-{level}
```

对于白色与黑色则无需定义level，即`text-black`与`text-white`

对于颜色，除了在文本中，在背景与边框等等也会涉及到，这类的原子类语法通常为

```
{text|bg|border}-{color}-{level}
```

#### 颜色不透明度

```
text-opacity-{level}
```

设置css值 `--tw-text-opacity: level/100;` 例如`text-opacity-50`为`--tw-text-opacity: 0.5;` 即50%透明度

#### 装饰

增加下划线，删除线装饰

| Class        | Properties                     |
| ------------ | ------------------------------ |
| underline    | text-decoration: underline;    |
| line-through | text-decoration: line-through; |
| no-underline | text-decoration: none;         |

#### 转化（大小写转换）

| Class       | Properties                  |
| ----------- | --------------------------- |
| uppercase   | text-transform: uppercase;  |
| lowercase   | text-transform: lowercase;  |
| capitalize  | text-transform: capitalize; |
| normal-case | text-transform: none;       |

#### 溢出

| Class             | Properties                                                   |
| ----------------- | ------------------------------------------------------------ |
| truncate          | overflow: hidden; text-overflow: ellipsis; white-space: nowrap; |
| overflow-ellipsis | text-overflow: ellipsis;                                     |
| overflow-clip     | text-overflow: clip;                                         |

使用 `truncate` 用省略号(`…`)来截断溢出的文本。（通常使用这个）

#### 对齐

| Class        | Properties           |
| ------------ | -------------------- |
| text-left    | text-align: left;    |
| text-center  | text-align: center;  |
| text-right   | text-align: right;   |
| text-justify | text-align: justify; |

水平对齐相对简单，但对于内联样式（行内样式），通常会碰到垂直方向不对齐的情况，就可以使用`vertical-align: middle`，垂直对齐相关的原子类

| Class             | Properties                   |
| ----------------- | ---------------------------- |
| align-baseline    | vertical-align: baseline;    |
| align-top         | vertical-align: top;         |
| align-middle      | vertical-align: middle;      |
| align-bottom      | vertical-align: bottom;      |
| align-text-top    | vertical-align: text-top;    |
| align-text-bottom | vertical-align: text-bottom; |

#### 空格

| Class               | Properties             |
| ------------------- | ---------------------- |
| whitespace-normal   | white-space: normal;   |
| whitespace-nowrap   | white-space: nowrap;   |
| whitespace-pre      | white-space: pre;      |
| whitespace-pre-line | white-space: pre-line; |
| whitespace-pre-wrap | white-space: pre-wrap; |

#### 换行

| Class        | Properties                                 |
| ------------ | ------------------------------------------ |
| break-normal | overflow-wrap: normal; word-break: normal; |
| break-words  | overflow-wrap: break-word;                 |
| break-all    | word-break: break-all;                     |

### 背景

#### 颜色

同text，语法一致。颜色的不透明度也一致。

```
bg-{color}-{level}
```

#### 位置

```
bg-{position}
```

#### 裁剪

[背景图像裁剪 - Tailwind CSS 中文文档](https://www.tailwindcss.cn/docs/background-clip)

| Class           | Properties                    |
| --------------- | ----------------------------- |
| bg-clip-border  | background-clip: border-box;  |
| bg-clip-padding | background-clip: padding-box; |
| bg-clip-content | background-clip: content-box; |
| bg-clip-text    | background-clip: text;        |

对于一些渐变色背景，可以直接按文本方式裁剪，可让文本呈现背景色。

#### 渐变色

[背景图像大小 - Tailwind CSS 中文文档](https://www.tailwindcss.cn/docs/background-size)

[渐变色停止 - Tailwind CSS 中文文档](https://www.tailwindcss.cn/docs/gradient-color-stops)

### 边框

#### 圆角

同字体大小，如`xs sm base lg xl`，语法规则为`rounded-{size}`。此外还可指定方向即`rounded-{t|r|b|l}-{size}`

使用 `rounded-full` 功能类来创建药丸形💊和圆圈

#### 厚度

```
border-{size}
border-{t|r|b|l}-{size}
```

要注意，这里的size对应的是px，1:1比例。如`border-4`为`border-width: 4px;` **不指定size则为1px**

#### 颜色

```
border-{color}
```

不透明度同理。

#### 样式

| Class         | Properties            |
| ------------- | --------------------- |
| border-solid  | border-style: solid;  |
| border-dashed | border-style: dashed; |
| border-dotted | border-style: dotted; |
| border-double | border-style: double; |
| border-none   | border-style: none;   |

#### 分割线

元素之间可以使用 `divid-{x/y}-{width}` 和 `divid-{color}` 功能类在子元素之间添加边框。参见[分割宽度](https://www.tailwindcss.cn/docs/divid-width)和[分割颜色](https://www.tailwindcss.cn/docs/divid-color)文档。

#### 轮廓环

创建带盒状阴影的轮廓环的功能类

```
 ring-{width} 
```

颜色 `ring-{color}`

css属性对应 `box-shadow: var(--tw-ring-inset) 0 0 0 calc(0px + var(--tw-ring-offset-width)) var(--tw-ring-color);`

通常可以与focus实现聚焦环，如`focus:ring-4`

### 盒阴影

语法 `shadow-{screen}`

还有个内阴影`shadow-inner`，取消阴影 `shadow-none`

### 过渡

使用 `transition-{properties}` 功能来指定哪些属性在变化时应该过渡。不指定则为 `background-color, border-color, color, fill, stroke, opacity, box-shadow, transform, filter, backdrop-filter;`

持续时间 `duration-{time}` time单位毫秒

缓和曲线  `ease-{timing}` 分别有`linear in out in-out`

###  动画

[动画 - Tailwind CSS 中文文档](https://www.tailwindcss.cn/docs/animation)

### 容器

要使一个容器居中，使用 `mx-auto` 功能类：

```html
<div class="container mx-auto">
  <!-- ... -->
</div>
```

### 总结

只记录了下常用的原子类相关，实际遇到样式需求，还会再从文档中查阅。不过这东西还是熟用熟记。

对于这类原子类编写样式，起初多半是难以适应，但使用过一段时间，了解大致原子类对于的css样式后，使用与开发效果会有一个质的提升。但对于大部分原子类都作为字符串并写在class中，难免会难以维护。所以就可以使用windicss中的属性化模式，将其改写为属性方式。

如果是Vue开发者的话，倒是更推荐使用windicss，会有更好的体验效果。
