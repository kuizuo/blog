---
slug: rust-wasm-md5
title: Rust实现MD5加密并打包成WebAssembly调用
date: 2023-01-04
authors: kuizuo
tags: [rust, wasm]
keywords: [rust, wasm]
image: https://img.kuizuo.me/2026/fb63cc8ba51feb4021e9cd8bffd54e6d.png
---

我初识 WebAssembly 是当初想要分析某个网站的加密算法，最终定位到了一个 `.wasm` 文件，没错，这个就是 WebAssembly 的构建产物，能够直接运行在浏览器中。在我当时看来这门技术很先进，不过如今看来绝大多数的 web 应用貌似都没使用上，迄今为止我也只在这个网站中看到使用 WebAssembly 的（也许有很多，只是没实质分析过）。

恰好最近正在接触 Rust，而 Rust 开发 WebAssembly 也非常方便，因此本文算是我对 Rust + WebAssembly 的初探。

{/* truncate */}

有关 [WebAssembly ](https://developer.mozilla.org/zh-CN/docs/WebAssembly)不做过多介绍，你可以到 [MDN](https://developer.mozilla.org/zh-CN/docs/WebAssembly) 中查看相关介绍。本文重点于 Rust + WebAssembly 实践与相关工具，在 [Rust and WebAssembly (github.com)](https://github.com/rustwasm) 或 [https://github.com/rwasm](https://github.com/rwasm) 中查看 rustwasm 相关生态。

## 使用 [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) 打包 rust 为 wasm 文件

下载 wasm-pack，用于将 rust 代码打包成 .wasm 文件

```bash
cargo install wasm-pack
```

使用 cargo 有可能无法安装 wasm-pack（笔者就安装不了 openssl-sys），可以到 [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) 官网下载对应的二进制文件进行安装。

### 构建 rust lib

```bash
cargo new --lib hello-wasm
```

将会创建 rust 库工程，并创建 `src/lib.rs`。修改为以下内容（先不必在意代码）

```rust title='src/lib.rs' icon='simple-icons:rust'
extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}

```

接着在 Cargo.toml 文件中添加 wasm-bindgen 依赖，`wasm-bindgen` 来提供 JavaScript 和 Rust 类型之间的桥梁，允许 JavaScript 使用字符串调用 Rust API，或调用 Rust 函数来捕获 JavaScript 异常。

```toml title='Cargo.toml' icon='logos:toml'
[package]
name = "hello-wasm"
version = "0.1.0"

[lib]
crate-type = ["cdylib"]

[dependencies]
wasm-bindgen = "0.2"

```

### 打包

```rust
wasm-pack build
```

WebAssembly 构建产物将会输出在 pkg 目录下，如下

```
├─pkg
|  ├─.gitignore
|  ├─hello_wasm.d.ts
|  ├─hello_wasm.js
|  ├─hello_wasm_bg.js
|  ├─hello_wasm_bg.wasm
|  └─hello_wasm_bg.wasm.d.ts
```

:::info

如果想当 npm 包发布的话，可以添加 —scope 参数，将会在 pkg 下生成 package.json 文件用于发布或当做一个 npm 包来使用，这样也可以在前端工程中直接当做一个模块来导入使用。

```bash
wasm-pack build --scope mynpmusername
```

:::

借助 [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) 可以非常轻松的将 rust 打包成 wasm，同时还提供了 js 相关支持。直接打包成 js 可导入的 npm 包，而不是让用户导入 wasm 文件然后通过浏览器 `WebAssembly` 对象来加载 WebAssembly 代码，其他语言的 WebAssembly 开发也是如此。

此外 [rustwasm](https://rustwasm.github.io/) 还提供了对应的模板 [rustwasm/wasm-pack-template](https://github.com/rustwasm/wasm-pack-template)，可以帮你省去上面的一系列配置操作，专注于你的 wasm 开发。

### 运行

由于上面我们已经将其打包成了一个 npm 包，只需要将配置好 package.json 的依赖即可，本地的话可通过下方格式，将 pkg 目录更改为 hello-wasm，并放置在根目录下。

```json title='package.json' icon='logos:nodejs-icon'
  "dependencies": {
    "hello-wasm": "file:./hello-wasm"
  },
```

这时候就可以通过 js 直接导入使用

```rust
const js = import("./hello-wasm/hello_wasm.js");
js.then(js => {
  js.greet("WebAssembly");
});
```

在 vite 生态中有个 [rwasm/vite-plugin-rsw](https://github.com/rwasm/vite-plugin-rsw) 插件，能够在 vite 中快速使用 wasm-pack。下文中的一个应用示例也将采用该插件进行开发。

## Rust 实现 MD5 算法

回到一开始的标题，在实现这个功能我一般会想 js 如何实现 MD5 算法，通常来说 MD5 算法是个比较流行的加密算法，通过搜索引擎能够快速帮我找到一份 js 的 MD5 算法。不过我更习惯通过包管理器导入的加密库，如[crypto-js](https://www.npmjs.com/package/crypto-js)。

同理，在 rust 中可以到 [crates.io](https://crates.io/) 中也可以找到你想要的库，如 [digest](https://crates.io/crates/digest)，不过我这里主要是实现 MD5 算法便使用的是 [md-5](https://crates.io/crates/md-5)。以下是我的封装代码。

```rust
use md5::{Digest, Md5};

fn md5(input: &str) -> String {
    let mut hasher = Md5::new();

    hasher.update(input.as_bytes());

    let result = hasher.finalize();
    format!("{:x}", result)
}

fn main() {
    let result = md5("123456");
    println!("{}", result);
}

```

然后将这一部分的代码替换到一开始的示例中。

```rust title='lib.rs' icon='simple-icons:rust'
extern crate wasm_bindgen;
extern crate md5;

use wasm_bindgen::prelude::*;
use md5::{Digest, Md5};

#[wasm_bindgen]
pub fn md5(input: &str)-> String {
    let mut hasher = Md5::new();

    hasher.update(input.as_bytes());

    let result = hasher.finalize();
    format!("{:x}", result)
}

```

此时通过 wasm-pack 将上述代码打包成 npm 包形式即可在 js 中调用 rust 提供的 md5 函数，至此就已经完成了本标题的内容了。

## 在项目中使用

这里我所借用 [rwasm/vite-plugin-rsw](https://github.com/rwasm/vite-plugin-rsw) 插件，在 vite 中配合 wasm-pack 进行开发的一个实例。代码部分就不做解读了，有兴趣可自行到翻阅源码：[kuizuo/rust-wasm-md5](https://github.com/kuizuo/rust-wasm-md5)

在线地址：[http://rust-wasm-md5.kuizuo.me](http://rust-wasm-md5.kuizuo.me/) （不保证地址长期可用）

![](https://img.kuizuo.me/_XHPNCbC-B.png)

## 思考：为何不使用 js 的 md5 而是 wasm 的 md5

众所周知，你在浏览器中按下 F12 打开 DevTools，并选择源代码面板中就可以看到当前访问的网站的所有代码。

![](https://img.kuizuo.me/6019y_U19n.png)

而对于一些具有熟练度的逆向分析者中，如果不经过任何处理的代码被打包到生产环境中能够快速的定位出某个功能的具体代码位置。

而通过 wasm 就能很有效的将代码隐藏起来，不让逆向分析者查看，就像下面这样

![](https://img.kuizuo.me/BbA3n6wFws.png)

![](https://img.kuizuo.me/81tgfDE_P7.png)

这里我并没有将 md5 更改成不易猜测的名字，你也可自行下断点尝试一番，定位代码。当你定位到具体代码后，就会得到上图的二进制代码格式，几乎无法解读其意思。

不过虽说解读不出 wasm 的原代码（至少目前来说很难反编译成原始代码），但可以通过扣代码的方式来调用 wasm 对外提供的函数（这里为 md5 函数）。

这里仅是 wasm 的一种实际用例，更多情况下应该还是用 Wasm 来提高 web 应用性能的。

## 相关链接

[编译 Rust 为 WebAssembly - WebAssembly | MDN (mozilla.org)](https://developer.mozilla.org/zh-CN/docs/WebAssembly/Rust_to_wasm)

[Rust and WebAssembly](https://rustwasm.github.io/)

[前端入门 ｜ Rust 和 WebAssembly - Rust 精选](https://rustmagazine.github.io/rust_magazine_2021/chapter_2/rust_wasm_frontend.html)

[rwasm/vite-plugin-rsw: 🦞 wasm-pack plugin for Vite (github.com)](https://github.com/rwasm/vite-plugin-rsw)
