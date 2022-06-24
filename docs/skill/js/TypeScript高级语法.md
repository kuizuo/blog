---
title: TypeScript高级语法
date: 2022-06-25
authors: kuizuo
tags: [typescript]
---

<!-- truncate -->

在线运行 TypeScript [https://www.typescriptlang.org/play](https://www.typescriptlang.org/play)

## typeof

```TypeScript
typeof val
```

获取对象的类型

1. 已知一个 javascript 变量，通过 typeof 就能直接获取其类型

```TypeScript
const str = 'foo'
typeof str === 'string' // true

const user = {
  name: 'kuizuo',
  age: 12,
  address: {
      province: '福建',
      city: '厦门'
  }
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

```TypeScript
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

```TypeScript
keyof T
```

获取 T 类型中的所有 key，类似与 Object.keys(object)

根据 key 获取对象其属性的例子

```TypeScript
function getProperty<T extends object, K extends keyof T>(obj: T, key: K) {
  return obj[key]
}
```

上面代码有很好的代码提示，并且如果获取的 key 不在其对象中，将会直接报错。

对于一些常用类型的 keyof 值

```TypeScript
type K0 = keyof string
// number | typeof Symbol.iterator | "toString" | "charAt" | ... more
type K1 = keyof boolean
// "valueOf"
type K2 = keyof number
// "toString" | "valueOf" | "toFixed" | "toExponential" | "toPrecision" | "toLocaleString"
type K3 = keyof any;
// string | number | symbol
```

## 映射类型

```TypeScript
{ [P in K]: T }
```

其中 in 类似与 for ...in 语句，而 T 类型表示任意类型。遍历 K 类型的所有 key，生成 P : T，例如

```TypeScript
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

```TypeScript
{ [ P in K] :T }
{ [ P in K] ?:T }
{ [ P in K] -?:T }

{ readonly [ P in K] :T }
{ readonly [ P in K] ?:T }
{ -readonly [ P in K] ?:T }

```

就可以实现一些 TypeScript 的内置工具类（给对象属性只读，可选等等）

```TypeScript
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

```TypeScript
T extends U ? X : Y
```

其代码语法类似与三元运算符，

1. 如果 T 和 U 都为基本类型两侧相同，则 extends 在语义上可以理解为 ===

```TypeScript
type Demo1 = 'foo' extends 'bar' ? true : false // false
type Demo2 = 'c' extends 'c' ? true : false // true
```

2. 若位于 extends 右侧的类型包含位于 extends 左侧的类型(即**狭窄类型 extends 宽泛类型**)时，结果为 true，反之为 false。

```TypeScript
type Demo3 = string extends string | number ? true : false // true
```

3. 当 extends 作用于**对象**时，若在对象中指定的 key 越多，则其类型定义的范围越狭窄。

```TypeScript
type Demo4 = { a: true, b: false } extends { a: true } ? true : false // true
```

4. 作用于联合类型中，且 T 为**裸类型参数**(无`T[] [T] Promise<T>` 等类型包装过)，那么则为**分布式条件类型**，对于该类型来说，当 T 为联合类型时，运算过程会被分解为多个分支（类似于乘法分配律），那么返回的类型也将是多个类型。

分布式条件类型的特点：“裸”类型、类型参数、联合类型参数会触发分支。

```TypeScript
type Demo5<T, U> = T extends U ? never : T
type Demo6 = Demo5<'a' | 'b' | 'c' | 'd', 'c' | 'd'> // 'a' | 'b'

```

例如上面定义的 Demo5，其实也就是 TypeScript 内置工具类的[Exclude<UnionType, ExcludedMembers>](https://www.typescriptlang.org/docs/handbook/utility-types.html#excludeuniontype-excludedmembers)的实现，所返回的结果是 `'a' | 'b'`，其内部的实现相当于

```TypeScript
'a' extends 'c' | 'd' ? never : 'a' // 'a'
'b' extends 'c' | 'd' ? never : 'b' // 'b'
'c' extends 'c' | 'd' ? never : 'c' // never
'd' extends 'c' | 'd' ? never : 'd' // never
// 执行四次条件类型,最终合并得到 'a' | 'b'

```

但如果 T 不能**裸类型参数**类型，那么便不会做**分布式条件类型**，返回的结果便只有一个。

## TypeScript 内置工具类

[TypeScript: Documentation - Utility Types (typescriptlang.org)](https://www.typescriptlang.org/docs/handbook/utility-types.html)

## 相关文档与练习

[TypeScript: JavaScript With Syntax For Types. (typescriptlang.org)](https://www.typescriptlang.org/)

[深入理解 TypeScript | 深入理解 TypeScript (jkchao.github.io)](https://jkchao.github.io/typescript-book-chinese/)

[type-challenges/type-challenges: Collection of TypeScript type challenges with online judge (github.com)](https://github.com/type-challenges/type-challenges)
