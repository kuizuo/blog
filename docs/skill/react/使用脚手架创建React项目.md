---
id: create-react-app
slug: /create-react-app
title: 使用脚手架创建React项目
date: 2021-09-15
authors: kuizuo
tags: [react]
keywords: [react]
---

<!-- truncate -->

## create-react-app

全局安装

```
npm install -g create-react-app

create-react-app my-app
cd my-app
npm start
```

或

```sh
npx create-react-app my-app
cd my-app
npm start
```

## umijs

先找个地方建个空目录。

```bash
mkdir myapp && cd myapp
```

通过官方工具创建项目

```bash
yarn create @umijs/umi-app
# 或 npx @umijs/create-umi-app

yarn
yarn start
```

### 创建 Ant-Design-Pro 项目

[开始使用 - Ant Design Pro](https://pro.ant.design/zh-CN/docs/getting-started)

```bash
# 使用 npm
npx create-umi myapp
# 使用 yarn
yarn create umi myapp
```

按照 umi 脚手架的引导，选择 ant-design-pro，TypeScript，（建议完整版）

```shell
? Select the boilerplate type (Use arrow keys)
❯ ant-design-pro  - Create project with a layout-only ant-design-pro boilerplate, use together with umi block.
  app             - Create project with a easy boilerplate, support typescript.
  block           - Create a umi block.
  library         - Create a library with umi.
  plugin          - Create a umi plugin.
```

然后进入目录，下载依赖，通过`npm run start`（一定要是这个命令），然后静等即可（实测 18 分钟左右，总之比我安装过的依赖都要久很多！200M 的宽带）

```shell
cd myapp && npm install
```

依赖文件 node_modules 大小为 713MB，占用空间 830MB，包含 99913 个文件，13788 个文件夹

顺便吐槽下我第一次启动的时候电脑所占用的资源（电脑 i7-9750H，16g 内存）

![image-20210902050243256](https://img.kuizuo.cn/image-20210902050243256.png)

## Vite

```
npm create vite@latest my-vue-app
```

选择 react 即可

![image-20220412161447441](https://img.kuizuo.cn/image-20220412161447441.png)
