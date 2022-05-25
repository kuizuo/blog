---
title: Docker部署Node项目
date: 2022-05-25
authors: kuizuo
tags: [docker, node]
---

<!-- truncate -->

[把一个 Node.js web 应用程序给 Docker 化 | Node.js (nodejs.org)](https://nodejs.org/zh-cn/docs/guides/nodejs-docker-webapp/)

## 部署Express项目

前提：准备一个Express项目以及Docker环境

在Express项目根目录下创建Dockerfile文件，内容如下

```dockerfile title="Dockerfile"
FROM node:alpine as builder

WORKDIR /app

COPY . .

RUN npm install

EXPOSE 3000

CMD ["npm", "run", "start"]
```

上述代码的大致意思如下

1. 下载node环境
2. 设置RUN CMD COPY ADD指令的工作目录
3. 拷贝宿主机（当前运行终端的位置）的文件到容器中的 app 目录中
4. 安装npm包
5. 暴露3000端口
6. 执行`npm run start`脚本命令

在执行命令前，还需要创建.dockerignore，将一些不必要的文件排除（其作用于.gitignore一致）

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

将会执行Dockerfile命令，待所有命令执行完毕后，将会创建my-app的镜像

执行启动容器命令，将服务启动。

```bash
docker run --name my-app -p 3000:3000 my-app
```

此时访问对应机器的3000端口即可访问express项目。

如果想打开容器内的终端，有以下两种选择

```
docker exec -it 容器ID/名 /bin/bash  # 进入后开启新的终端 可在里面操作(常用) 或者为/bin/sh
docker attach 容器ID/名 # 不会启动新的进程 单单只是进入容器的终端
```

## 部署Express+MongoDB+Redis

假设我现在要部署 Express + MongoDB+Redis的服务的话，可以使用docker-compose.yml来自动化部署多个容器。

创建docker-compose.yml文件，内容如下

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

运行命令，**重新部署的话可以添加--build参数**

```
docker-compose up -d 
```

:::danger

web后端项目中涉及到，数据库的连接地址（Host）要以docker-compose.yml中的service名一致。例如上面所定义的environment中

MYSQL_HOST=mysql

REDIS_HOST=redis

而不能为localhost，因为**docker容器内的localhost与宿主机的localhost并不是同一个地址**。

或者是在配置中将localhost修改为docker网络的ip，一般为172.17.0.1，具体根据docker实际网络而定。

:::
