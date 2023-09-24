**阅读须知**

本文将不涉及：

*   如何获得 Rustup（Rust编程语言推荐工具链管理程序）
*   如何在各平台安装 Rustup （尽管下文会涉及到 Rustup 加速镜像有哪些可用）

**使用国内镜像加速更新 Rustup 工具链**

## 配置环境变量
我们需要指定 `RUSTUP_DIST_SERVER`（默认指向 https://static.rust-lang.org）和 `RUSTUP_UPDATE_ROOT` （默认指向https://static.rust-lang.org/rustup），这两个网站均在中国大陆境外，因此在中国大陆访问会很慢，需要配置成境内的镜像。

以下 `RUSTUP_DIST_SERVER` 和 `RUSTUP_UPDATE_ROOT` 可以组合使用。

```
# 清华大学
RUSTUP_DIST_SERVER=https://mirrors.tuna.tsinghua.edu.cn/rustup

# 中国科学技术大学
RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup

# 上海交通大学
RUSTUP_DIST_SERVER=https://mirrors.sjtug.sjtu.edu.cn/rust-static/
```

## 配置到crate配置文件中
**使用国内镜像加速更新 crate(板条箱) 拉取**

将如下配置写入 `$HOME/.cargo/config` 文件：

```
# 放到 `$HOME/.cargo/config` 文件中
[source.crates-io]
registry = "https://github.com/rust-lang/crates.io-index"

# 替换成你偏好的镜像源
replace-with = 'sjtu'

# 清华大学
[source.tuna]
registry = "https://mirrors.tuna.tsinghua.edu.cn/git/crates.io-index.git"

# 中国科学技术大学
[source.ustc]
registry = "git://mirrors.ustc.edu.cn/crates.io-index"

# 上海交通大学
[source.sjtu]
registry = "https://mirrors.sjtug.sjtu.edu.cn/git/crates.io-index"

# rustcc社区
[source.rustcc]
registry = "git://crates.rustcc.cn/crates.io-index"
```

**参考资料**

Rustup 镜像安装帮助 - 清华大学: https://mirrors.tuna.tsinghua.edu.cn/help/rustup/ Rust Toolchain 反向代理使用帮助 - 中国科学技术大学: https://mirrors.ustc.edu.cn/help/rust-static.html 国内Rust库文件镜像 - rustcc: https://rustcc.cn/article?id=0d125ec2-08fe-427a-9328-69cba6c4795c 在中国大陆cargo(货物)命令速度很慢怎么办? \- rustcc/RustFAQ: https://github.com/rustcc/RustFAQ#%E5%9C%A8%E4%B8%AD%E5%9B%BD%E5%A4%A7%E9%99%86cargo%E5%91%BD%E4%BB%A4%E9%80%9F%E5%BA%A6%E5%BE%88%E6%85%A2%E6%80%8E%E4%B9%88%E5%8A%9E