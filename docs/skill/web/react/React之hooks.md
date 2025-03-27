---
id: react-hooks
slug: /react-hooks
title: React之hooks
date: 2022-09-07
authors: kuizuo
tags: [react, hook]
keywords: [react, hook]
---

<!-- truncate -->

## 官方内置 hooks

### useState

在函数组件中管理数据状态

#### 基本数据类型

```tsx
import React from 'react'

export function App(props) {
  const [count, setCount] = React.useState(0)

  return (
    <div className='App'>
      <div>{count}</div>
      <button onClick={() => setCount(() => count + 1)}>add</button>
      <button onClick={() => setCount(count + 1)}>add</button>
      <button onClick={() => setCount(c => c + 1)}>add</button>
    </div>
  )
}
```

主要注意的点是 setCount 可以传入相应数值或匿名函数，如上所示的都是可以实现对 count+1

#### 对象

这里主要针对复杂类型（数组，对象），示例：

```tsx
import * as React from 'react'

export default function App(props) {
  type User = {
    name: string
    age: number
  }

  const [user, setUser] = React.useState<User>({
    name: 'kuizuo',
    age: 20,
  })

  return (
    <div className="App">
      <div>{user.name}</div>
      <div>{user.age}</div>
      <button
        onClick={() => {
          setUser((obj) => ({
            ...obj,
            name: '愧怍',
          }))
        }}
      >
        set name as 愧怍
      </button>
    </div>
  )
}
```

#### 数组

```tsx
import * as React from 'react'

export default function App(props) {
  const [arr, setArr] = React.useState(['code', 'eat', 'sleep'])

  return (
    <div className="App">
      {arr.map((a) => (
        <div>{a}</div>
      ))}
      <button
        onClick={() => {
          setArr((arr) => [...arr, '123'])
        }}
      >
        append
      </button>
    </div>
  )
}

```

useState 对于复杂类型而言，尤其是在赋值操作是比较麻烦的。没办法，因为需要更改状态就需要调用 setState 方法，而 setState 方法需要传入最终完整的数据。

对于对象而言，可以考虑使用 react use 的 [useMap](https://github.com/streamich/react-use/blob/master/docs/useMap.md)，对于数组而言，可以考虑使用 react use 的 [useList](https://github.com/streamich/react-use/blob/master/docs/useList.md)。（其实都是对 setState 进行一定的封装）

### useEffect

useEffect 可以让你在函数组件中执行副作用操作

副作用是指一段和当前执行结果无关的代码，常用的副作用操作如数据获取、设置订阅、手动更改 React 组件中的 DOM。

useEffect 可以接收两个参数，代码如下：

```TypeScript
useEffect(callback, dependencies)
```

第一个参数是要执行的函数 callback，第二个参数是可选的依赖项数组 dependencies。

以下是一些示例：

```tsx
import * as React,{} from 'react'

export default function App() {
  const [count, setCount] = React.useState(0)

  React.useEffect(()=>{
    console.log(count)
  })

  return <div onClick={() => setCount(count+1)}>{count}</div>
}
```

每当 count 发生变化后，useEffect 副作用函数就会输出 count，由于没传入 dependencies 数组，则**每次 render 后执行**

如果第二个参数给空数组的话，只会在**第一次加载组件时执行**，通常可用于首次数据请求。

```tsx
import * as React from 'react'

export default function App() {
  const [data, setData] = React.useState('')

  React.useEffect(() => {
    async function fetchData() {
      const data = await (await fetch('https://api.kuizuo.cn/api/one')).text()
      console.log(data)
      setData(data)
    }

    fetchData()
  }, [])

  return <div>{data}</div>
}

```

此外 componentWillUnmount 生命周期也可在 useEffect 中执行。

```tsx
import * as React from 'react'

export default function App() {
  const [data, setData] = React.useState('')

  React.useEffect(() => {
    // Update the document title using the browser API
    document.title = `You clicked ${count} times`

    return () => {
        // 可用于做清除，相当于 class 组件的 componentWillUnmount
    }

  }, [count]) // 指定依赖项为 count，在 count 更新时执行该副作用

  return <div onClick={() => setCount(count+1)}>{count}</div>
}
```

#### 小总结

useEffect 提供了四种执行副作用的时机：

- **每次 render 后执行**：不提供第二个依赖项参数。比如 `useEffect(() => {})`
- **仅第一次 render 后执行**：提供一个空数组作为依赖项。比如 `useEffect(() => {}, [])`
- **第一次以及依赖项发生变化后执行**：提供依赖项数组。比如 `useEffect(() => {}, [deps])`
- **组件 unmount 后执行**：返回一个回调函数。比如 `useEffect(() => { return () => {} }, [])`

### useMono

useMemo 定义的创建函数只会在某个依赖项改变时才重新计算，有助于每次渲染时**不会重复的高开销的计算**，而接收这个计算值作为属性的组件，也**不会频繁地需要重新渲染**。类似与 Vue 中的 computed

示例：

```tsx
const memoizedValue = useMemo(() => computeExpensiveValue(a, b), [a, b])
```

useMemo 本质上就像一个缓存，而依赖项是缓存失效策略。

不仅能对数据进行缓存，对于纯组件也是能够缓存的。使用`memo` 对组件进行包裹即可，例如 `export default React.memo(Children)`

### useCallback

useCallback 定义的回调函数只会在依赖项改变时重新声明这个回调函数，这样就保证了**组件不会创建重复的回调函数**。而接收这个回调函数作为属性的组件，也**不会频繁地需要重新渲染**。

useCallback 与 useMono 的作用都是一样的，只不过前者专门为函数构建的。例如下面的一个例子

```tsx
const handleMegaBoost = React.useMemo(() => {
  return function() {
    setCount((currentValue) => currentValue + 1234)
  }
}, [])
```

有更好的方法，就是使用 useCallback，如下

```tsx
const handleMegaBoost = React.useCallback(() => {
  setCount((currentValue) => currentValue + 1234)
}, [])
```

这两者的效果是完全相同的。相当于

```tsx
// This:
React.useCallback(function helloWorld(){}, [])
// ...Is functionally equivalent to this:
React.useMemo(() => function helloWorld(){}, [])
```

对于 useMono 和 useCallback 强烈推荐阅读[Understanding useMemo and useCallback (joshwcomeau.com)](https://www.joshwcomeau.com/react/usememo-and-usecallback/)

### useRef

useRef 返回一个 ref 对象，这个 ref 对象在组件的整个生命周期内持续存在。

他有 2 个用处：

- 保存 DOM 节点的引用
- 在多次渲染之间共享数据

保存 DOM 节点的引入使用示例如下：

```tsx
function TextInputWithFocusButton() {
  const inputEl = React.useRef(null)
  const onButtonClick = () => {
    // `current` 指向已挂载到 DOM 上的文本输入元素
    inputEl.current.focus()
  }
  return (
    <>
      <input ref={inputEl} type='text' />
      <button onClick={onButtonClick}>Focus the input</button>
    </>
  )
}
```

以上代码通过 useRef 创建了 ref 对象，保存了 DOM 节点的引用，可以对 ref.current 做 DOM 操作。

第二个用途在日常开发中没怎么用到过，useRef 主要还是为了获取 dom 属性。

### useContext

useContext 用于接收一个 context 对象并返回该 context 的值，可以实现**跨层级的数据共享**。

```tsx
// 创建一个 context 对象
const MyContext = React.createContext(initialValue)
function App() {
  return (
    // 通过 Context.Provider 传递 context 的值
    <MyContext.Provider value='1'>
      <Container />
    </MyContext.Provider>
  )
}

function Container() {
  return <Test />
}

function Test() {
  // 获取 Context 的值
  const theme = useContext(MyContext) // 1
  return <div></div>
}

```

更倾向的做法是将`const MyContext = React.createContext(initialValue)` 存在在`src/contexts`目录下，以便于其他组件引用

### useReducer

语法：`const [state, dispatch] = useReducer(reducer, initialArg, init)`

第一个参数 reducer 是函数 `(state, action) => newState`，接受当前的 state 和操作行为。第二个参数 initialArg 是状态初始值。第三个参数 init 是懒惰初始化函数。

示例：

```tsx
import * as React from 'react'
import './style.css'

const initialState = { count: 0 }

function reducer(state, action) {
  switch (action.type) {
    case 'increment':
      return { count: state.count + 1 }
    case 'decrement':
      return { count: state.count - 1 }
    default:
      throw new Error()
  }
}

export default function Counter() {
  const [state, dispatch] = React.useReducer(reducer, initialState)
  return (
    <div>
      Count: {state.count}
      <button onClick={() => dispatch({ type: 'decrement' })}>-</button>
      <button onClick={() => dispatch({ type: 'increment' })}>+</button>
    </div>
  )
}
```

通过`useReducer `与`useContext` 就能做到代替[redux](https://cn.redux.js.org/) 来进行状态管理了。篇幅有限，这里占不做演示。

### useId

这是 React18 的新特性，用于同一个组件在服务端和客户端之间确定对应的匹配关系。而确定关系的便是这个 Id。

当一个组件，同时会被服务端和客户端渲染时，我们就可以使用 `useId` 来创建当前组件的唯一身份。

```tsx
function Checkbox() {
  const id = useId()
  return (
    <>
      <label htmlFor={id}>Do you like React?</label>
      <input id={id} type="checkbox" name="react"/>
    </>
  )
}
```

如果在同一个组件中，我们需要多个 id，那么一定不要重复的使用 `useId`，而是基于一个 id 来创建不同的标识，通常的做法是添加额外不同的字符串，例如下面这样：

```tsx
function NameFields() {
  const id = useId()
  return (
    <div>
      <label htmlFor={id + '-firstName'}>First Name</label>
      <div>
        <input id={id + '-firstName'} type="text" />
      </div>
      <label htmlFor={id + '-lastName'}>Last Name</label>
      <div>
        <input id={id + '-lastName'} type="text" />
      </div>
    </div>
  )
}
```

更多 React 内置 Hook 可以参考 [Hook API](https://zh-hans.reactjs.org/docs/hooks-reference.html)

## 自定义 hooks

自定义 Hooks 就是函数，它有 2 个特征区分于普通函数：

- 名称以 “use” 开头；
- 函数内部调用其他的 Hook。

例如：

### useToggle

```tsx
import * as React from 'react'
function useToggle(initialValue) {
  const [value, setValue] = React.useState(initialValue)
  const toggle = React.useCallback(() => {
    setValue(v => !v)
  }, [])
  return [value, toggle]
}
```

等等根据实际应用场景编写相应的 hooks

## Hooks 库

[react-use](https://github.com/streamich/react-use)

[ahooks](https://ahooks.js.org/zh-CN/)

## 参考文章

[React-你有完全了解 Hooks 吗](https://juejin.cn/post/7064345263061598222)
