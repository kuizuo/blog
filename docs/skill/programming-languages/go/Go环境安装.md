---
id: go-environment-install
slug: /go-environment-install
title: Go环境安装
date: 2021-09-01
authors: kuizuo
tags: [go]
keywords: [go]
---

<!-- truncate -->

## 安装 Go

[golang.org](https://golang.org/)

[go 下载地址](https://studygolang.com/dl)

[GoLand](https://www.jetbrains.com/go/download/download-thanks.html)

下载安装包，选择路径，默认下一步即可

## 配置环境变量

**GOROOT 即为 GO 的安装目录。**设置为 `E:\Go`

**GOPATH 即为存储 Go 工具依赖的路径**，可以自己进行设值，我放在了 GoWorks 自己建的，里面需要包含 src、pkg、bin 三个目录。 设置为 `E:\GoWork`

## 配置 Go 代理

[GOPROXY.IO - 一个全球代理 为 Go 模块而生](https://goproxy.io/zh/)

windows

```bash
# 设置goproxy.io代理
go env -w GOPROXY="https://proxy.golang.com.cn,direct"
# 设置GO111MOUDLE
go env -w GO111MODULE="on"

```

临时设置(不推荐)

```bash
# 配置 GOPROXY 环境变量
$env:GOPROXY = "https://proxy.golang.com.cn,direct"
# 还可以设置不走 proxy 的私有仓库或组，多个用逗号相隔（可选）
$env:GOPRIVATE = "git.mycompany.com,github.com/my/private"
```

mac/linux 下

```bash
# 配置 GOPROXY 环境变量
export GOPROXY=https://proxy.golang.com.cn,direct
# 还可以设置不走 proxy 的私有仓库或组，多个用逗号相隔（可选）
export GOPRIVATE=git.mycompany.com,github.com/my/private
```

### 常用的 go 代理

- goproxy [https://goproxy.io/zh/](https://goproxy.io/zh/)
- 阿里云 [https://mirrors.aliyun.com/goproxy/](https://mirrors.aliyun.com/goproxy/)
- 七牛云 [https://goproxy.cn](https://goproxy.cn)

可输出 go env 查看环境

## 配置 VSCode 开发环境

[VsCode 中 Golang Tools 使用 · 语雀 (yuque.com)](https://www.yuque.com/flipped-aurora/gqbcfk/lidsv6)

这里使用的是 VSCode 进行开发，在扩展程序中安装 Go 插件，输入

- `command` + `shift` + `p` 输入 Go:Show All Commands 选择 Go:Install/Update Tools，选择所有工具，并确定安装。

![image-20210901044224765](https://img.kuizuo.cn/image-20210901044224765.png)

控制台输出安装结果

![image-20210901044323709](https://img.kuizuo.cn/image-20210901044323709.png)

或者打开命令提示符（以管理员身份打开）输入

```bash
go get -v github.com/mdempsky/gocode
go get -v github.com/uudashr/gopkgs/v2/cmd/gopkgs
go get -v github.com/rogpeppe/godef
go get -u github.com/ramya-rao-a/go-outline
go get -v github.com/sqs/goreturns
```

安装 go 的开发依赖，比如语法提示，包提示等等。安装完成后，就此配置完成 Vscode 的 Go 开发环境。

## Goland

没什么好说的，大部分配置无需操作即可使用，不过个人还是倾向于使用 VSCode。
