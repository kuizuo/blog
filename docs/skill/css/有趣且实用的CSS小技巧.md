---
id: func-and-useful-css-tips
title: 有趣且实用的CSS小技巧
date: 2022-02-23
authors: kuizuo
tags: [css]
---

刷到一篇文章 [有趣且实用的 CSS 小技巧](https://mp.weixin.qq.com/s/Gos-IvUWtudHmRJfRMtzrw) ，对一些 CSS 技巧感到有趣，于是打算自己试试，顺带记录一些相关 CSS 的 API，以便未来某些时刻用到。

<!-- truncate -->

import BrowserWindow from '@site/src/components/BrowserWindow';
import CodeBlock from '@theme/CodeBlock';

### 打字效果

import TypewritingSource from '!!raw-loader!./components/typewriting';
import Typewriting from './components/typewriting';

<BrowserWindow>

<Typewriting></Typewriting>

</BrowserWindow>

<CodeBlock className="language-jsx">{TypewritingSource}</CodeBlock>

[animation - CSS（层叠样式表） | MDN (mozilla.org)](https://developer.mozilla.org/zh-CN/docs/Web/CSS/animation)

主要使用到动画 animation 可分为两段

第一段: typing 2s steps(22) 在两秒内将文字分为22段显示，也就呈现打字的效果。

第二段：blink 0.5s step-end infinite alternate; 每0.5秒光标闪烁，无限交替


### 阴影效果

import ShadowSource from '!!raw-loader!./components/shadow';
import Shadow from './components/shadow';

<BrowserWindow>

<Shadow></Shadow>

</BrowserWindow>

<CodeBlock className="language-jsx">{ShadowSource}</CodeBlock>

### 平滑滚动

import Scroll from './components/scroll';

<BrowserWindow>

<Scroll></Scroll>

</BrowserWindow>

[scroll-behavior - CSS（层叠样式表） | MDN (mozilla.org)](https://developer.mozilla.org/zh-CN/docs/Web/CSS/scroll-behavior)

只需一行 CSS：`scroll-behavior: smooth`

### 截断文本

<BrowserWindow>

```jsx live
function Ellipsis() {
  return (
    <div
      style={{
        width: '200px',
        backgroundColor: '#fff',
        padding: '10px',
        overflow: 'hidden',
        whiteSpace: 'nowrap',
        textOverflow: 'ellipsis',
      }}
    >
      白日依山尽，黄河入海流。欲穷千里目，更上一层楼。
    </div>
  )
}
```

</BrowserWindow>

主要这三行代码

```css
overflow: hidden;
white-space: nowrap;
text-overflow: ellipsis;
```

- overflow: hidden; 溢出隐藏。

- white-space: nowrap; 是强制显示为一行

- text-overflow: ellipsis; 将文本溢出显示为（…）

如果元素没有宽度限制，那么不会省略，要多行省略可以使用 `-webkit-line-clamp` 需要浏览器提供支持

```css
overflow: hidden;
text-overflow: ellipsis;
display: -webkit-box;
-webkit-line-clamp: 3;
-webkit-box-orient: vertical;
```

### 自定义滚动条

import ScrollBar from './components/scrollBar';
import ScrollBarSource from '!!raw-loader!./components/scrollBar';

<BrowserWindow>

<ScrollBar></ScrollBar>

</BrowserWindow>

<CodeBlock className="language-jsx">{ScrollBarSource}</CodeBlock>

[::-webkit-scrollbar - CSS（层叠样式表） | MDN (mozilla.org)](https://developer.mozilla.org/zh-CN/docs/Web/CSS/::-webkit-scrollbar)


有以下伪元素选择器去修改各式webkit浏览器的滚动条样式:

- ::-webkit-scrollbar — 整个滚动条.
- ::-webkit-scrollbar-button — 滚动条上的按钮 (上下箭头).
- ::-webkit-scrollbar-thumb — 滚动条上的滚动滑块.
- ::-webkit-scrollbar-track — 滚动条轨道.
- ::-webkit-scrollbar-track-piece — 滚动条没有滑块的轨道部分.
- ::-webkit-scrollbar-corner — 当同时有垂直滚动条和水平滚动条时交汇的部分.
- ::-webkit-resizer — 某些元素的corner部分的部分样式(例:textarea的可拖动按钮).


### 提示框

import Tooltip from './components/tooltip';
import TooltipSource from '!!raw-loader!./components/tooltip';

<BrowserWindow>

<Tooltip></Tooltip>

</BrowserWindow>

<CodeBlock className="language-jsx">{TooltipSource}</CodeBlock>

使用到 CSS 函数 `attr()`，可创建动态的纯 CSS 提示框


### 渐变边框(渐变色)

import Gradient from './components/gradient';
import GradientSource from '!!raw-loader!./components/gradient';

<BrowserWindow>

<Gradient></Gradient>

</BrowserWindow>

<CodeBlock className="language-jsx">{GradientSource}</CodeBlock>

[使用 CSS 渐变 - CSS（层叠样式表） | MDN (mozilla.org)](https://developer.mozilla.org/zh-CN/docs/Web/CSS/CSS_Images/Using_CSS_gradients)


列几个渐变色的网站

渐变色按钮: [Buttons with CSS gradients - Gradient Buttons (colorion.co)](https://gradientbuttons.colorion.co/)

简单的配色网站: [uiGradients - Beautiful colored gradients](https://uigradients.com/#Tranquil)

提供大量配色: [Gradient Colors Collection Palette - CoolHue 2.0 (webkul.github.io)](https://webkul.github.io/coolhue/)