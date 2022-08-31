---
id: typescript-advanced-grammar
slug: /typescript-advanced-grammar
title: TypeScript高级语法
date: 2022-06-25
authors: kuizuo
tags: [typescript]
keywords: [typescript]
---

<!-- truncate -->

在线运行 TypeScript [https://www.typescriptlang.org/play](https://www.typescriptlang.org/play)

## typeof

```typescript
typeof val
```

获取对象的类型

1. 已知一个 javascript 变量，通过 typeof 就能直接获取其类型

```typescript
const str = 'foo'
typeof str === 'string' // true

const user = {
  name: 'kuizuo',
  age: 12,
  address: {
    province: '福建',
    city: '厦门',
  },
}

type User = typeof user
// {
//   name: string;
//   age: number;
//   address: {
//      province: string;
//      city: string;
//   };
// }

type Address = typeof user['address']
// {
//    province: string;
//    city: string;
// }
```

2. 获取函数的类型（参数类型与返回值类型）

```typescript
function add(a: number, b: number): number {
  return a + b
}

type AddType = typeof add
// (a: number, b: number) => number

type AddReturnType = ReturnType<typeof add>
// number

type AddParameterType = Parameters<typeof add>
// [a: number, b: number]
```

## keyof

```typescript
keyof T
```

获取 T 类型中的所有 key，类似与 Object.keys(object)

根据 key 获取对象其属性的例子

```typescript
function getProperty<T extends object, K extends keyof T>(obj: T, key: K) {
  return obj[key]
}
```

上面代码有很好的代码提示，并且如果获取的 key 不在其对象中，将会直接报错。

对于一些常用类型的 keyof 值

```typescript
type K0 = keyof string
// number | typeof Symbol.iterator | "toString" | "charAt" | ... more
type K1 = keyof boolean
// "valueOf"
type K2 = keyof number
// "toString" | "valueOf" | "toFixed" | "toExponential" | "toPrecision" | "toLocaleString"
type K3 = keyof any
// string | number | symbol
```

## 交叉类型

& 交叉运算符

类似集合中的交集，满足以下特性

1. 唯一性：A & A 等价于 A
2. 满足交换律：A & B
3. 满足结合律：(A & B) & C 等价于 A & (B & C)
4. 父类型收敛：如果 B 是 A 的父类型，那么 A & B 将收敛为 A 类型.

任何与 never 交叉的类型都是 nerver，any 交叉的类型为 any（除了 nerver）

```typescript
type A0 = any & 1 // any
type A1 = any & boolean // any
type A2 = any & never // never

type A3 = string & number // never
```

## 映射类型

```typescript
{ [P in K]: T }
```

其中 in 类似与 for ...in 语句，而 T 类型表示任意类型。遍历 K 类型的所有 key，生成 P : T，例如

```typescript
interface Todo {
  title: string
  description: string
  completed: boolean
}

type Demo<T> = { [P in keyof T]: T }
type Todo1 = Demo<Todo>
// {
//   title: string
//   description: string
//   completed: boolean
// }
```

上面代码看似没有任何映射关系，因为在映射类型中可以给对其添加`readonly `和 `?` 只读与可选修饰符，以及`+` `-` 增加与删除修饰符（默认为+）例如

```typescript
{ [ P in K] :T }
{ [ P in K] ?:T }
{ [ P in K] -?:T }

{ readonly [ P in K] :T }
{ readonly [ P in K] ?:T }
{ -readonly [ P in K] ?:T }

```

就可以实现一些 TypeScript 的内置工具类（给对象属性只读，可选等等）

```typescript
type MyPick<T, K extends keyof T> = {
  [P in K]: T[P]
}

type MyPartial<T> = {
  [P in keyof T]?: T[P]
}

type MyRequired<T> = {
  [P in keyof T]-?: T[P];
}

type MyReadonly<T> = {
  readonly [P in keyof T]: T[P]
}

...
```

## 条件类型

```typescript
T extends U ? X : Y
```

其代码语法类似与三元运算符，

1. 如果 T 和 U 都为基本类型两侧相同，则 extends 在语义上可以理解为 ===

```typescript
type Demo1 = 'foo' extends 'bar' ? true : false // false
type Demo2 = 'c' extends 'c' ? true : false // true
```

2. 若位于 extends 右侧的类型包含位于 extends 左侧的类型(即**狭窄类型 extends 宽泛类型**)时，结果为 true，反之为 false。

```typescript
type Demo3 = string extends string | number ? true : false // true
```

3. 当 extends 作用于**对象**时，若在对象中指定的 key 越多，则其类型定义的范围越狭窄。

```typescript
type Demo4 = { a: true; b: false } extends { a: true } ? true : false // true
```

4. 作用于联合类型中，且 T 为**裸类型参数**(无`T[] [T] Promise<T>` 等类型包装过)，那么则为**分布式条件类型**，对于该类型来说，当 T 为联合类型时，运算过程会被分解为多个分支（类似于乘法分配律），那么返回的类型也将是多个类型。

分布式条件类型的特点：“裸”类型、类型参数、联合类型参数会触发分支。

```typescript
type Demo5<T, U> = T extends U ? never : T
type Demo6 = Demo5<'a' | 'b' | 'c' | 'd', 'c' | 'd'> // 'a' | 'b'
```

例如上面定义的 Demo5，其实也就是 TypeScript 内置工具类的[Exclude<UnionType, ExcludedMembers>](https://www.typescriptlang.org/docs/handbook/utility-types.html#excludeuniontype-excludedmembers)的实现，所返回的结果是 `'a' | 'b'`，其内部的实现相当于

```typescript
'a' extends 'c' | 'd' ? never : 'a' // 'a'
'b' extends 'c' | 'd' ? never : 'b' // 'b'
'c' extends 'c' | 'd' ? never : 'c' // never
'd' extends 'c' | 'd' ? never : 'd' // never
// 执行四次条件类型,最终合并得到 'a' | 'b'

```

但如果 T 不能**裸类型参数**类型，那么便不会做**分布式条件类型**，返回的结果便只有一个。

## 类型推断

```typescript
type Demo<T> = T extends (infer U)[] ? U : T
```

如果 T 为`string[]`类型，那么 infer 可以推导出 U 为 string 类型

注：infer 只能在**条件类型的`extends`子句**中才允许`infer`声明，且只能**在条件分支中 true 中**使用

下列语句都将报错

```typescript
type Wrong1<T extends (infer U)[]> = T[0]

type Wrong2<T> = (infer U)[] extends T ? U : T

type Wrong3<T> = T extends (infer U)[] ? T : U
```

一些例子

```typescript
type Unpacked<T> = T extends (infer U)[] ? U : T extends (...args: any[]) => infer U ? U : T extends Promise<infer U> ? U : T

type T0 = Unpacked<string> // string
type T1 = Unpacked<string[]> // string
type T2 = Unpacked<() => string> // string
type T3 = Unpacked<Promise<string>> // string
type T4 = Unpacked<Promise<string>[]> // Promise<string>
type T5 = Unpacked<Promise<string> | string> // string | Promise<string>
```

通过 infer 就可以推导出函数的参数类型与返回值类型

```typescript
const fn = (v: boolean) => {
  if (v) return 1
  else return 2
}

type MyReturnType<T> = T extends (...args: any[]) => infer R ? R : any

type MyParameterType<T> = T extends (...args: infer P) => any ? P : any

type FnReturnType = MyReturnType<typeof fn>
// 1 | 2
type FnParameterType = MyParameterType<typeof fn>
// [v: boolean]
```

## 声明文件

我个人习惯会在根目录创建 types 文件夹，里面存放 d.ts 声明文件，同时 tsconfig.json 中配置 `"include": ["src/**/*.ts", "types/**/*.d.ts"]`

创建一个全局声明文件`global.d.ts`，使用 declare 关键字来声明

```typescript title="global.d.ts"
declare module 'foo' {
  export var bar: number
}
```

此时就可以在其他文件中`import * as foo from 'foo'`，即便没有安装 foo 模块，但是 foo 依然有 bar 属性提示，这在一些第三方使用 js 所编写的库中经常遇到。在例如我想给我的 axios 封装些自己定义的代码，同时还带有类型提示，那么就可以使用声明文件，如下

```typescript title="global.d.ts"
import * as axios from 'axios'

declare module 'axios' {
  export interface Axios {
    myget: (url: string, config?: AxiosRequestConfig) => Promise<AxiosResponse>
  }
}
```

```typescript title="demo.ts"
import axios, { AxiosRequestConfig } from 'axios'

axios.myget = async (url: string, config?: AxiosRequestConfig) => {
  console.log(url)
  return axios.get(url, config)
}
```

## type 和 interface 区别

### 相同点

1. 都可以用来描述对象或函数

2. 类型别名和接口都支持扩展

```typescript
type User = {
  name: string
}

type User1 = User & { age: number }
```

```typescript
interface User {
  name: string
}

interface User1 extends User {
  age: number
}
```

### 不同点

1. 同名接口会自动合并，而类型别名不会

```typescript
interface User {
  name: string
}

interface User {
  age: number
}

const user: User = {
  name: 'kuizuo',
  age: 20,
}
```

```typescript
type User = {
  name: string
}

type User = {
  age: number
}
// 标识符“User”重复。
```

### 使用场景

#### type 的使用场景

- 定义基本类型
- 定义元组类型
- 定义函数类型
- 定义联合类型
- 定义映射类型

#### interface 的使用场景

- 利用接口自动合并特性，在第三方库中可以对其进行接口扩展

- 定义对象类型且无需使用 type 时

## TypeScript 内置工具类

[TypeScript: Documentation - Utility Types (typescriptlang.org)](https://www.typescriptlang.org/docs/handbook/utility-types.html)

## 相关文档与练习

[TypeScript: JavaScript With Syntax For Types. (typescriptlang.org)](https://www.typescriptlang.org/)

[深入理解 TypeScript | 深入理解 TypeScript (jkchao.github.io)](https://jkchao.github.io/typescript-book-chinese/)

[type-challenges/type-challenges: Collection of TypeScript type challenges with online judge (github.com)](https://github.com/type-challenges/type-challenges)
