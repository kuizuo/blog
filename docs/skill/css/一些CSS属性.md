---
id: css-properties
slug: /css-properties
title: 一些CSS属性
date: 2022-08-12
authors: kuizuo
tags: [css]
keywords: [css]
---

最近在写一些 CSS 样例，可以在 [前端示例代码库](https://example.kuizuo.cn/) 中查看，后续也会把一些灵感和设计放在这上面，不过这里主要介绍我之前没怎么用到过的一些 CSS 属性（奇技淫巧），通过这些特性能非常方便的实现一些需求，不会做过多使用介绍，具体可查看 [MDN](https://developer.mozilla.org/zh-CN/docs/Web/CSS) 与 [示例源代码](https://github.com/kuizuo/example)。

可在这个网站 [Can I use](https://caniuse.com/) 查看 CSS 兼容情况。

<!-- truncate -->

## [clip-path](https://developer.mozilla.org/zh-CN/docs/Web/CSS/clip-path)

如果要实现多边形的话，之前的做法通常是使用 border 来实现的，但是用 border 来实现的是比较复杂的，最关键的是不好用。[**`clip-path`**](https://developer.mozilla.org/zh-CN/docs/Web/CSS/clip-path) CSS 属性使用裁剪方式创建元素的可显示区域。可以在这个网站 [Clippy — CSS clip-path 生成器](https://www.html.cn/tool/css-clip-path/) 勾勒出所要的图形，然后将其添加至 css 属性即可。

![](https://secure2.wostatic.cn/static/qs1brMUAga5NbQhpbMU5d6/image.png)

## [linear-gradient](https://developer.mozilla.org/zh-CN/docs/Web/CSS/gradient/linear-gradient)

线性渐变颜色，也是渐变色用到最多的一个属性，此外还有径向 [`radial-gradient`](https://developer.mozilla.org/zh-CN/docs/Web/CSS/gradient/radial-gradient)与圆锥[conic-gradient](https://developer.mozilla.org/zh-CN/docs/Web/CSS/gradient/conic-gradient)

```css
/* 渐变轴为45度，从蓝色渐变到红色 */
linear-gradient(45deg, blue, red);

/* 从右下到左上、从蓝色渐变到红色 */
linear-gradient(to left top, blue, red);

/* 从下到上，从蓝色开始渐变、到高度 40% 位置是绿色渐变开始、最后以红色结束 */
linear-gradient(0deg, blue, green 40%, red);
```

不过这个属性只适用于背景(background)颜色，如果想要在文字，边框，阴影中使用渐变颜色，通常需要先设置渐变背景颜色，然后通过一些 css 属性“裁剪”出相应的部分。

这里的“裁剪”主要用到 background-clip 属性，如果想要裁剪出文字可以 `background-clip: text`配合文字`color: transparent`，要裁剪出边框可以 `background-clip: content-box, border-box;`，在给背景颜色添加原背景色。

## [backdrop-filter](https://developer.mozilla.org/zh-CN/docs/Web/CSS/backdrop-filter)

**`backdrop-filter`** [CSS](https://developer.mozilla.org/zh-CN/docs/Web/CSS) 属性可以让你为一个元素后面区域添加图形效果（如模糊或颜色偏移）。因为它适用于元素*背后*的所有元素，为了看到效果，必须使元素或其背景至少部分透明。

为背景添加滤镜，比如毛玻璃效果 `backdrop-filter: blur(5px);` 、灰度`backdrop-filter: grayscale(1);`等等。

再次之前要实现这类效果还需要使用[filter](https://developer.mozilla.org/zh-CN/docs/Web/CSS/filter)属性（兼容性更好），然后用伪元素双背景的方式来实现，实在过于麻烦。

# [-webkit-box-reflect](https://developer.mozilla.org/en-US/docs/Web/CSS/-webkit-box-reflect)

可以实现类似水下倒影的效果，例如

```
-webkit-box-reflect: below 0 linear-gradient(transparent, transparent, rgba(0, 0, 0, 0.4));
```

## [aspect-ratio](https://developer.mozilla.org/zh-CN/docs/Web/CSS/aspect-ratio)

例如

```css
aspect-ratio: 1 / 1;
aspect-ratio: 16 / 9;
aspect-ratio: 4 / 3;
```

## [gap](https://developer.mozilla.org/zh-CN/docs/Web/CSS/gap)

这个属性我经常用到，主要**用于 flex 与 grid 布局中用于设置元素间的间隔**，原本这个属性是只有 grid 布局中才有的，后来在 flex 布局中也可以使用。

## [writing-mode](https://developer.mozilla.org/zh-CN/docs/Web/CSS/writing-mode)

修改文字显示方向，例如竖行显示 `writing-mode: vertical-lr;`

![img](https://developer.mozilla.org/en-US/docs/Web/CSS/writing-mode/screenshot_2020-02-05_21-04-30.png)

## 总结

此外还有很多特性也在不断了解，每年也会有一些新的特性来帮助开发者更好的使用 css 去美化网站。

最直接的体验就是到 [CSS（层叠样式表） | MDN](https://developer.mozilla.org/zh-CN/docs/Web/CSS) ，在 MDN 上能查到关于前端开发技术的文档，可以说是前端的百科全书了。
