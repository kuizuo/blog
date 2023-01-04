---
slug: react-css-implementation
title: React中Css几种实现方案
date: 2022-01-14
authors: kuizuo
tags: [react, css]
keywords: [react, css]
---

<!-- truncate -->

## 全局样式

与传统 html 标签类属性不同，react 中 class 必须编写为 className，比如

全局 css

```jsx
.box {
  background-color:red;
  width:300px;
  height:300px;
}
```

js

```jsx
function Hello() {
  return <div className='box'>hello react</div>
}

ReactDOM.render(<Hello />, document.getElementById('root'))
```

与传统在 html 标签定义 css 样式不同，因为这不是传统的 html 代码，而是 JSX，由于 class 作为关键字，无法作为标识符出现，比方说下面的代码将会报错。

```jsx
const { class } = { class: 'foo' } // Uncaught SyntaxError: Unexpected token }
const { className } = { className: 'foo' }
const { class: className } = { class: 'foo' }
```

关于官方也有对此问题回答

[有趣的话题，为什么 jsx 用 className 而不是 class](https://www.jackpu.com/you-qu-de-hua-ti-wei-shi-yao-jsxyong-classnameer-bu-shi-class/)

所以把传统的 html 代码强行搬运到 react 中，如果带有 class 与 style 属性，那么将会报错。

## 内联样式

内联样式也得写成对象 key-value 形式，遇到-连字符，则需要大写，如

```jsx
function Hello() {
  return (
    <div className='box' style={{ fontSize: '32px', textAlign: 'center' }}>
      hello react
    </div>
  )
}
```

CSS 的`font-size`属性要写成`fontSize`，这是 JavaScript 操作 CSS 属性的[约定](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Properties_Reference)。

其实{ } 可传入表达式，比方这里传入的就是`{ fontSize: "32px",textAlign: "center" }` 对象，也可以将其定义为一个变量传入。

但是写内联样式显得组丑陋影响阅读，并且样式不易于复用，同时伪元素与媒体查询无法实现，但是封装成类样式，又会影响到全局作用域，所以便有了局部样式`styles.module.css` 。

## 局部样式 CSS Modules

Css Modules 并不是 React 专用解决方法，适用于所有使用 webpack 等打包工具的开发环境。以 webpack 为例，在 css-loader 的 options 里打开`modules：true` 选项即可使用 Css Modules。一般配置如下

```js
{
  loader: "css-loader",
  options: {
    importLoaders: 1,
    modules: true,
    localIdentName: "[name]__[local]___[hash:base64:5]"  // 为了生成类名不是纯随机
  },
},

```

然后通过 import 引入

```jsx
import styles from './styles.module.css'

function Hello() {
  return <div className={styles.box}>hello react</div>
}
```

但如果是有多个局部样式，直接拼接是无效的（毕竟是个无效的表达式）

```jsx
// 错误
<div className={style.class1 style.class2}</div>

// 正确
<div className={`${style.class1} ${style.class2}`}</div>
<div className={style.class1+ " " +style.class2}</div>
<div className={[style.class1,style.class2].join(" ")}</div>

```

### classnames

还可以通过 npm 包 classnames 来定义类名，如

```jsx
import classnames from 'classnames'
import styles from './styles.module.css'

;<div className={classnames(styles.class1, styles.class2)}></div>
```

最终都将编译为

```jsx
<div class='class1 class2'></div>
```

当然 classnames 还有多种方式添加，就不列举了，主要针对复杂样式，根据条件是否添加样式。

但是 在 Css Module 中，其实能发现挺多问题的

如果类名是带有-连字符`.table-size`那么就只能`styles["table-size"]` 来引用，并且都必须使用`{style.className}` 形式。

最主要的是，css 都写在 css 文件中，无法处理动态 css。

## CSS in JS

由于 React 对 CSS 的封装非常弱，导致了一系列的第三方库，用来加强 CSS 操作，统称为 CSS in JS，有一种在 js 文件中写 css 代码的感觉，根据不完全统计，各种 CSS in JS 的库至少有[47 种](https://github.com/MicheleBertoli/css-in-js)，其中比较出名的 便是[styled-components](https://link.juejin.cn/?target=https://github.com/styled-components/styled-components)。

```jsx
import styled from 'styled-components'

// `` 和 () 一样可以作为js里作为函数接受参数的标志，这个做法类似于HOC，包裹一层css到h1上生成新组件Title
const Title = styled.h1`
  font-size: 1.5em;
  text-align: center;
  color: palevioletred;

  span {
    font-size: 2em;
  }
`

// 在充分使用css全部功能的同时，非常方便的实现动态css， 甚至可以直接调用props！
const Wrapper = styled.section`
  padding: 4em;
  background: ${(props) => props.bgColor};
`

const Button = styled.a`
  /* This renders the buttons above... Edit me! */
  display: inline-block;
  border-radius: 3px;
  padding: 0.5rem 0;
  margin: 0.5rem 1rem;
  width: 11rem;
  background: transparent;
  color: white;
  border: 2px solid white;
  /* The GitHub button is a primary button
   * edit this to target it specifically! */
  ${(props) =>
    props.primary &&
    css`
      background: white;
      color: palevioletred;
    `}
`

const App = () => (
  <Wrapper bgColor='papayawhi'>
    <Title>
      <span>Hello World</span>, this is my first styled component!
    </Title>
    <Button href='https://github.com/styled-components/styled-components' target='_blank' rel='noopener' primary>
      GitHub
    </Button>
  </Wrapper>
)
```

像上面的 Title，Wrapper，Button 都是组件，Title 本质就是一个 h1 标签，在通过模板字符串编写局部 css 样式。

能直接编写子元素的样式，以及`& :hover`等 Sass 语法。

根据传入属性，在 css 中使用，Wrapper 传入背景颜色属性，Button 判断是否为 primary。

并且能方便的给暴露`className` props 的三方 UI 库上样式：

```jsx
const StyledButton = styled(Button)` ... `
```

## styled-jsx

[vercel/styled-jsx: Full CSS support for JSX without compromises (github.com)](https://github.com/vercel/styled-jsx)

styled-jsx 概括第一印象就是 React css 的 vue 解决。`yarn add styled-jsx` 安装后，不用`import`，而是一个 babel 插件，`.babelrc`配置：

```JavaScript
{
  "plugins": [
    "styled-jsx/babel"
  ]
}

```

使用

```jsx

render () {
    return <div className='table'>
        <div className='row'>
            <div className='cell'>A0</div>
            <div className='cell'>B0</div>
        </div>
        <style jsx>{`
          .table {
            margin: 10px;
          }
          .row {
            border: 1px solid black;
          }
          .cell {
            color: red;
          }
    `}</style>
    </div>;
}

```

只会作用到同级标签作用域，可以说是一种另类的内联样式了，如果不喜欢将样式写在 render 里，styled-jsx 提供了一个 `css` 的工具函数：

```jsx
import css from 'styled-jsx/css'

export default () => (
  <div>
    <button>styled-jsx</button>
    <style jsx>{button}</style>
  </div>
)

const button = css`
  button {
    color: hotpink;
  }
`
```

补充：现在我更推荐使用 Emotion。

## 原子类

简单说，就是将常用的 css 样式都封装完，只需要在 class 中引入即可

这里选用当红框架 [Tailwind CSS](https://www.tailwindcss.cn/) 作为演示。

比方说 flex 布局的话，就需要写 `dispaly: flex;` 但是封装成类，如

```CSS
.flex {
  dispaly: flex;
}
```

引用的时候直接在 class 中添加 flex 即可

```jsx
<h1 class='flex'>tailwindcss</h1>
```

贴一张官方演示图，把大部分常用的样式都封装成 class

官方在线例子（下图） [Tailwind Play (tailwindcss.com)](https://play.tailwindcss.com/)

![](https://img.kuizuo.cn/20220114033240.png)

有以下几种优点：

1. 源代码无非就是 css 的基本样式，如 class `w-auto` 对应 css `width: auto;` 等等
2. 如果不是特别复杂的样式，甚至可以不用写一条 css 代码，开发效率杠杠的。
3. 体积很小，更好的样式复用，并且打包后会根据所用的 class 进行打包，而非全部无用样式打包。
4. 与 bootstrap 设计不同，完全可以定制化不同类型的组件，而不是像 `class="btn btn-danger"` 这样。

体验下来基本上就是在写内联样式 inline css 但是同时又不显得杂乱。

### 组件化中使用

在组件化开发中，完全可以自己实现一个 Button 按钮（上间距 `pt-4`，底部间距 `pb-10`，文字为 `text-sky-500` 天蓝色），

```jsx
const Button = ({ children, color }) => (
    <a className=`pt-4 pb-10 text-sky-500 ${color}`>{children}</a>
)
```

不过要说缺点的话：

1. 可能之前标题只需要定义.title 类来完成全部样式，而 tailwind 需要好几个 css 原子类来实现
2. 初学者可能不适应，需要反复的查阅文档。（不过用多了，自然就会习惯了）

然后还有一个 WindCSS，可以看作是**按需供应的** Tailwind 替代方案。不过暂时不支持 React。

此外还有一篇文章非常推荐 [重新构想原子化 CSS (antfu.me)](https://antfu.me/posts/reimagine-atomic-css-zh)，不多说，再刷一遍。

## 最佳实现？

介绍完几种 React 中 Css 的实现（当然还有很多库没介绍，主要挑几种主流的），实际又要选择哪种呢？

说说我目前 react 所选的操作，tailwind（原子类）+ CSS modules，写一些小项目或者 demo 甚至都没必要写 css 代码，毕竟 css 是大多数前端程序员都不是那么想写的（包括我）。而做一些自定义的小组件的话那肯定是 styled-components，而 styled-jsx，对组件代码牺牲挺大所以不怎么写。

不过每个人使用风格不同，我一开始接触原子类是 windicss，用久了之后习惯了常用的 class，编写起来可以说是相当的快捷了。

不过相比 Vue 而言，react 的 css 实现着实费劲。

> 参考链接：
>
> [CSS Modules 用法教程 - 阮一峰的网络日志 (ruanyifeng.com)](https://www.ruanyifeng.com/blog/2016/06/css_modules.html)
>
> [CSS in JS 简介 - 阮一峰的网络日志 (ruanyifeng.com)](https://www.ruanyifeng.com/blog/2017/04/css_in_js.html)
>
> [React 拾遗：从 10 种现在流行的 CSS 解决方案谈谈我的最爱 （下） - 掘金 (juejin.cn)](https://juejin.cn/post/6844903638289252360)
