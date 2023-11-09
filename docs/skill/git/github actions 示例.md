---
id: github-actions-example
slug: github-actions-example
title: github actions示例
date: 2021-10-01
authors: kuizuo
tags: [github, action]
keywords: [github, action]
---

<!-- truncate -->

[GitHub Marketplace · Actions to improve your workflow](https://github.com/marketplace?type=actions)


## 测试 输出

[Environment variables - GitHub Docs](https://docs.github.com/cn/actions/learn-github-actions/environment-variables)

[Contexts - GitHub Docs](https://docs.github.com/cn/actions/learn-github-actions/contexts#github-context)

```yaml title='print.yml'
name: Print
on: push

jobs:
  print-job:
    name: Print Job
    runs-on: ubuntu-latest
    steps:
    - name: Print a greeting
      env:
        MY_VAR: Hi there! My name is
        NAME: Kuizuo
      run: |
        echo $MY_VAR $NAME.

    - name: Print github info
      run: |
      	echo github owner: ${{ github.repository_owner }}
      	echo github repository: ${{ github.repository }}
        echo github workspace ${{ github.workspace }}

```

## 前端项目代码 lint 与 test

[Setup Node.js environment · Actions · GitHub Marketplace](https://github.com/marketplace/actions/setup-node-js-environment)

```yaml title='lint.yml'
name: Lint

on:
  push:
    branches:
      - main

  pull_request:
    branches:
      - main

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install pnpm
        uses: pnpm/action-setup@v2

      - name: Set node
        uses: actions/setup-node@v3
        with:
          node-version: 16.x
          cache: pnpm

      - name: Setup
        run: npm i -g @antfu/ni

      - name: Install
        run: nci

      - name: Lint
        run: nr lint
```

```yaml title='test.yml'
name: Test

on:
  push:
    branches:
      - main

  pull_request:
    branches:
      - main

jobs:
  test:
    runs-on: ${{ matrix.os }}

    strategy:
      matrix:
        node: [14.x, 16.x]
        os: [ubuntu-latest]
      fail-fast: false

    steps:
      - uses: actions/checkout@v3

      - name: Install pnpm
        uses: pnpm/action-setup@v2

      - name: Set node ${{ matrix.node }}
        uses: actions/setup-node@v3
        with:
          node-version: ${{ matrix.node }}
          cache: pnpm

      - run: corepack enable

      - name: Setup
        run: npm i -g @antfu/ni

      - name: Install
        run: nci

      - name: Build
        run: nr build

      - name: Test
        run: nr test

      - name: Typecheck
        run: nr typecheck
```

也可将 jobs 整合在一个文件内

## 发布到 GitHub Pages

[GitHub Pages action](https://github.com/marketplace/actions/github-pages-action)

```yaml
name: Build and Deploy
on:
  push:
    branches:
      - main
jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Install and Build
        run: |
          yarn install
          yarn run build

      - name: Deploy
        uses: peaceiris/actions-gh-pages@v3
        with:
          personal_token: ${{ secrets.ACCESS_TOKEN }}
          publish_dir: ./dist
```

publish_dir 为打包后的文件夹.

## ssh 部署

[ssh deploy · Actions · GitHub Marketplace](https://github.com/marketplace/actions/ssh-deploy)

```yaml
name: ci

on:
  push:
    branches:
      - main

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Use Node.js 16
        uses: actions/setup-node@v3
        with:
          node-version: '16.x'

      - name: Build Project
        run: |
          yarn install
          yarn run build

      - name: SSH Deploy
        uses: easingthemes/ssh-deploy@v2.2.11
        env:
          SSH_PRIVATE_KEY: ${{ secrets.PRIVATE_KEY }}
          ARGS: '-avzr --delete'
          SOURCE: 'build'
          REMOTE_HOST: ${{ secrets.REMOTE_HOST }}
          REMOTE_USER: 'root'
          TARGET: '/www/wwwroot/blog'
```

SSH_PRIVATE_KEY 是 SSH 密钥，可通过 `ssh-keygen` （生成位置/root/.ssh）或通过服务器管理面板的来生成密钥。后者的话需要绑定服务器实例，并且需要关机，我个人推荐使用后者。

## ftp 文件传输

```yaml
      - name: FTP Deploy
        uses: SamKirkland/FTP-Deploy-Action@4.0.0
        with:
          server: ${{ secrets.ftp_server }}
          username: ${{ secrets.ftp_user }}
          password: ${{ secrets.ftp_pwd }}
          local-dir: ./build/
          server-dir: ./
```

## 发布 release / npm 包

[changesets/action (github.com)](https://github.com/changesets/action)

```yaml title='release.yml'
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: Install pnpm
        uses: pnpm/action-setup@v2

      - name: Set node
        uses: actions/setup-node@v3
        with:
          node-version: 16.x
          cache: pnpm
          registry-url: 'https://registry.npmjs.org'

      - run: npx changelogithub
        continue-on-error: true
        env:
          GITHUB_TOKEN: ${{secrets.GITHUB_TOKEN}}

      - name: Install Dependencies
        run: pnpm i

      - name: PNPM build
        run: pnpm run build

      - name: Publish to NPM
        run: pnpm -r publish --access public --no-git-checks
        env:
          NODE_AUTH_TOKEN: ${{secrets.NPM_TOKEN}}

      - name: Publish to VSCE & OVSX
        run: npm run publish
        working-directory: ./packages/vscode
        env:
          VSCE_TOKEN: ${{secrets.VSCE_TOKEN}}
          OVSX_TOKEN: ${{secrets.OVSX_TOKEN}}
```

## 添加状态徽章 status badge

[Adding a workflow status badge - GitHub Docs](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/adding-a-workflow-status-badge)

创建一个工作流会自动生成状态徽章，地址如下

```
https://github.com/<OWNER>/<REPOSITORY>/actions/workflows/<WORKFLOW_FILE>/badge.svg
```

示例：

```
https://github.com/kuizuo/github-action-example/actions/workflows/ci.yml/badge.svg
```