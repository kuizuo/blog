---
id: docker-deploy-node-project
slug: /docker-deploy-node-project
title: Docker部署Node项目
date: 2022-05-25
authors: kuizuo
tags: [docker, node]
keywords: [docker, node]
---

<!-- truncate -->

[把一个 Node.js web 应用程序给 Docker 化 | Node.js (nodejs.org)](https://nodejs.org/zh-cn/docs/guides/nodejs-docker-webapp/)

## 部署 Express 项目

前提：准备一个 Express 项目以及 Docker 环境

在 Express 项目根目录下创建 Dockerfile 文件，内容如下

```dockerfile title="Dockerfile"
FROM node:alpine as builder

WORKDIR /app

COPY . .

RUN npm install

EXPOSE 3000

CMD ["npm", "run", "start"]
```

上述代码的大致意思如下

1. 下载 node 环境
2. 设置 RUN CMD COPY ADD 指令的工作目录
3. 拷贝宿主机（当前运行终端的位置）的文件到容器中的 app 目录中
4. 安装 npm 包
5. 暴露 3000 端口
6. 执行`npm run start`脚本命令

在执行命令前，还需要创建.dockerignore，将一些不必要的文件排除（其作用于.gitignore 一致）

```dockerfile title=".dockerignore"
/dist
/node_modules
package-lock.json
yarn.lock
```

此时打开终端，输入

```bash
docker build -t my-app .
```

将会执行 Dockerfile 命令，待所有命令执行完毕后，将会创建 my-app 的镜像

执行启动容器命令，将服务启动。

```bash
docker run --name my-app -p 3000:3000 my-app
```

此时访问对应机器的 3000 端口即可访问 express 项目。

如果想打开容器内的终端，有以下两种选择

```
docker exec -it 容器ID/名 /bin/bash  # 进入后开启新的终端 可在里面操作(常用) 或者为/bin/sh
docker attach 容器ID/名 # 不会启动新的进程 单单只是进入容器的终端
```

## 部署 Express+MongoDB+Redis

假设我现在要部署 Express + MongoDB+Redis 的服务的话，可以使用 docker-compose.yml 来自动化部署多个容器。

创建 docker-compose.yml 文件，内容如下

```yaml title="docker-compose.yml"
version: '3.9'

services:
  mongodb:
    image: mongo:4.4.6
    restart: always
    ports:
      - 27017:27017
    networks:
      - backend
    environment:
      MONGO_INITDB_ROOT_USERNAME: root
      MONGO_INITDB_ROOT_PASSWORD: 123
    volumes:
      - db-data:/data/db

  redis:
    image: redis:latest
    command:
      - /bin/bash
      - -c
      - redis-server --appendonly yes
    ports:
      - 6379:6379
    networks:
      - backend

  web:
    build: .
    restart: always
    environment:
      - NODE_ENV=development
      - MYSQL_HOST=mysql
      - REDIS_HOST=redis
    ports:
      - 5000:5000
    networks:
      - backend
    depends_on:
      - mongodb
      - redis

networks:
  backend:

volumes:
  db-data:
```

运行命令，**重新部署的话可以添加--build 参数**

```
docker-compose up -d
```

:::danger

web 后端项目中涉及到，数据库的连接地址（Host）要以 docker-compose.yml 中的 service 名一致。例如上面所定义的 environment 中

MYSQL_HOST=mysql

REDIS_HOST=redis

而不能为 localhost，因为**docker 容器内的 localhost 与宿主机的 localhost 并不是同一个地址**。

或者是在配置中将 localhost 修改为 docker 网络的 ip，一般为 172.17.0.1，具体根据 docker 实际网络而定。

:::
