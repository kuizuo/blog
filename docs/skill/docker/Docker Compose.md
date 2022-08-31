---
id: docker-compose
slug: /docker-compose
title: Docker Compose
date: 2021-05-26
authors: kuizuo
tags: [docker]
keywords: [docker]
---

<!-- truncate -->

## 简介

dockerfile 能让程序在任何地方运行 比如 web 服务 redis mysql nginx 但需要启动多个容器 并且都需要 run 一下 ,而通过 Docker Compose 则可以一键完成上面任务 实现自动化部署

**一句话:将多个容器融合在一起**

## 安装

前提需要安装 docker

1、下载

```shell
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# 上为官方的地址 可能有些慢 下为daocloud
sudo curl -L https://get.daocloud.io/docker/compose/releases/download/1.25.1/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose

```

2、授权文件权限

```shell
sudo chmod +x /usr/local/bin/docker-compose
```

3、测试安装结果

```
docker-compose --version
```

## 使用

```
docker-compose up
```

### YAML 规则

[Compose file version 3 reference | Docker Documentation](https://docs.docker.com/compose/compose-file/compose-file-v3/#compose-file-structure-and-examples)

`Compose` 中有两个重要的概念：

- 服务 (`service`)：一个应用的容器，实际上可以包括若干运行相同镜像的容器实例。
- 项目 (`project`)：由一组关联的应用容器组成的一个完整业务单元，在 `docker-compose.yml` 文件中定义。

一个简单的 YAML 配置文件就像下面这样。

```yaml
version: '3' # compose版本 根据docker的版本来匹配

services: # 服务
  服务1:
    # 服务配置
    images:
    build:
    ports:
    network:
    environment:
    depends_on:
  服务2:
networks:
volumes:
```
