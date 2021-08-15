---
to: blog/<%= h.date() %>-<%= name %>.md
---
---
id: <%= name %>
title: 
author: 愧怍
author_title: 前端工程师 / B站UP主
author_url: https://github.com/zxuqian
author_image_url: https://tvax3.sinaimg.cn/crop.0.0.1080.1080.180/b2745d44ly8g8s4muqeggj20u00u0n0k.jpg?KID=imgbed,tva&Expires=1582389585&ssig=EvXmyu%2FXsX
description: 
tags: [前端, React]
---

import useBaseUrl from '@docusaurus/useBaseUrl';

<!-- [B 站视频 - 点击传送]() -->


## 你将学到的

上一张效果图：

<img alt="" src={useBaseUrl('img/2020-03-15-learn-react-props-buttons/2020-03-15-19-02-33.png')} />

<!-- truncate -->


[源码：Github - React-Examples](https://github.com/zxuqian/react-examples)

## 创建 React 工程

1. 使用 create-react-app 创建一个工程：

   ```bash
   yarn create react-app react-button-props
   ```

   等同于

   ```bash
   npx create-react-app react-button-props
   ```



## 创建 Button 组件

1. 在 `src` 下边新建一个 `Button` 文件夹。组件应该有自己独立的文件夹，所有跟这个组件有关的文件，比如 css、hooks 等都放到一起，这样在查看一个组件源码时，相应的文件都会在一块，方便查找。另外也方便和其他人共享这个组件，它是一个独立的整体。
2. 在 `Button` 文件夹创建 `index.js` 文件，里边放用来定义按钮组件的代码。
3. 在 `Button` 文件夹下创建 `style.modules.css` 文件，在这里咱们先用普通的 css 来定义按钮的样式，后续的教程里我再给你介绍`styled-components`。它是一个 css-in-js 的解决方案

   :::important CSS modules 的作用
   这个带 modules 的 css 文件使用了 `css modules` 库，它是 create-react-app 工具里自带的，用来避免全局 class 名字冲突，在普通 css 下，如果不同的样式文件都同时使用了 `.button` 这样的 class 名，那么后面的就会把前面的覆盖。使用了`css modules`之后，它会自动生成随机的 class 名字。这样这个组件里边定义的 class 就不会被其他组件定义的同名的 class 给覆盖。当然你也可以不用它，有些全局的 css 可以直接定义在普通的 css 文件里。
   :::

4. 编写 `button` 组件的代码：

   ```jsx
   import React from "react";

   function Button(props) {
     return <button>{props.children}</button>;
   }

   export default Button;
   ```

   react 中的组件默认都会被传递一个 `props` 属性，里边会默认包含一个 children 属性，也就是说在使用 `<Button />` 组件时，两个标签中间所有的代码都会当作 children 传递进来。上边的代码，也可以使用 rest 操作符简化：

   ```jsx
   function Button({ children }) {
     return <button>{children}</button>;
   }
   ```

5. 删除 App 的 return 中的所有的代码，导入 Button 组件，然后把它写在 return 里边：

   ```jsx
   function App() {
     return <Button>默认按钮</Button>;
   }
   ```

## 编写 Button 默认样式

1. 打开 Button 组件下的 `style.modules.css` 文件，写上下边的 css 代码：

   ```css
   .button {
     padding: 12px 48px;
     border-radius: 24px;
     background-color: #0076ff;
     box-shadow: 0px 4px 10px rgba(135, 167, 171, 0.5);
     font-size: 14px;
     color: white;
     font-weight: 500;
     text-shadow: 0px 0.5px 1px rgba(0, 0, 0, 0.15);
     outline: none;
     cursor: pointer;
   }
   ```

   这里把按钮设置了背景、圆角边框、字体、指针样式和阴影。

2. 打开 Button 组件的 index.js 文件，导入 css 文件并赋值给一个变量，这里叫 `styles`：

   ```jsx
   import styles from "./styles.module.css";
   ```

3. 给 Button 组件加上 className 属性，这里可以用 `styles.button` 来访问 css 文件中的 `.button` 的样式：

   ```jsx
   <button className={styles.button}>{children}</button>
   ```

   可以在页面上看到，这个默认按钮的样式已经加载好了。

## 用 Props 给 Button 不同的样式

在给 Button 写完默认样式之后，咱们再来定义它几个变体，比如红色、黑色。你可以在 Button 里多添加一个 color 属性，代表其他组件使用它时，可以传递一个 color 属性，Button 会根据它的值显示不同的颜色，这里我假设它有三种，一种是默认的蓝，就是不传 color 的时候的颜色，一种是红色，color 的值为 red 的时候显示，一种是黑色，在 color 为 black 的时候显示。首先咱们先把这两种颜色的 css 样式定义好：

```css
.red {
  background-color: #ff4059;
}

.black {
  background-color: #2e3434;
}
```

### classnames 组合样式

在定义完这两个额外的样式之后，需要把它和`.button`定义的样式组合起来。这里可以手动去拼，也可以用之前刚开始安装的 classnames 依赖库。它可以根据条件来组合 className，只有满足一定条件的 class 才会被组合进来，在咱们这里，可以这样使用：

```jsx
<button
  className={classNames(styles.button, {
    [styles.red]: color === "red",
    [styles.black]: color === "black"
  })}
>
  {children}
</button>
```

它接收多个参数，第一个直接传递了 styles.button 这个 class，说明它无论其它属性怎么变化，它都是要有的，最后传递了一个对象，对象的 key 是 styles 中的 class 的名字，value 是 boolean 类型的，需要一个条件，返回 true 就把这个 class 加到组合中，false 就不加。那这里，如果 color 的值是 red，那么 button 中就会有 `.red` 定义的样式。

再在 App.js 中添加两个按钮 ，一个 color 设置为 red，一个 color 设置为 black:

```jsx
<main>
  <div>
    <Button>默认按钮</Button>
    <Button color="red">红色按钮</Button>
    <Button color="black">黑色按钮</Button>
  </div>
</main>
```

需要注意的是，react 要求在返回的 JSX 中只能有一个顶级的标签，不能有并列的多个，比如不能同时写三个 button，需要把它们包装在一个大的标签下，这里我用了一个 main，作为内容容器，里边有一个 div 是 button 的容器。

### 线框样式

如果再加一组线框样式的按钮呢？很简单，我再加一个`type`属性，默认是`primary`的，主要按钮，线框按钮的 type 叫它`secondary` 次要按钮，然后 classnames 添加一个新的 class，在 type 为 `secondary` 的时候追加到组合中：

```jsx
function Button({ children, type = "primary", color = "blue" }) {
  return (
    <button
      className={classNames(styles.button, {
        [styles.red]: color === "red",
        [styles.black]: color === "black",
        [styles.secondary]: type === "secondary"
      })}
    >
      {children}
    </button>
  );
}
```

接下来定义 `secondary` 样式：

```css
.secondary {
  background: none;
  border: 2px solid #0076ff;
  color: #0076ff;
}

.secondary.red {
  border-color: #ff4059;
  color: #ff4059;
}

.secondary.black {
  border-color: #2e3434;
  color: #2e3434;
}
```

在这里我把默认蓝色、红色、黑色按钮的边框和文字都设置了不同的颜色。

## 显示所有按钮样式

在 App.js 中咱们显示所有不同属性的按钮，然后给按钮容器加上一个 className，用来对按钮进行排版，这里我直接用了普通的 css 样式，也就是创建工程时给生成好的 App.css，直接把它导入进来：

App.js

```jsx
// 省略函数定义
<main>
  <div className="btn__container">
    <Button>默认按钮</Button>
    <Button color="red">红色按钮</Button>
    <Button color="black">黑色按钮</Button>
    <Button type="secondary">线框按钮</Button>
    <Button type="secondary" color="red">
      线框按钮
    </Button>
    <Button type="secondary" color="black">
      线框按钮
    </Button>
  </div>
</main>
```

App.css

```css
main {
  width: 100vw;
  height: 100vh;
  background-color: #f2f2f2;
  display: flex;
  align-items: center;
  justify-content: center;
}

.btn__container {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  column-gap: 24px;
  row-gap: 24px;
  align-content: center;
  justify-items: center;
}
```

好了，这个使用 React Props 来展示不同样式的按钮到这里就结束了，里边几个概念：

- React 组件默认会传递 Props 参数
- 使用 props 可以传递任何自定义的属性
- 组件相关的文件都放到一个文件夹里
- `css modules` - 用来生成随机局部 class 名字
- `classnames` - 用来组合多个 class

你学会了吗？如果有问题，欢迎通过下方链接参与讨论。

[>> 在 B 站参与讨论]()

