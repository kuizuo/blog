---
id: docker
slug: /docker
title: Docker笔记
date: 2021-05-26
authors: kuizuo
tags: [docker]
keywords: [docker]
---

<!-- truncate -->

[官方文档](https://docs.docker.com/engine/install/centos/)

[Docker — 从入门到实践 (gitbook.io)](https://yeasy.gitbook.io/docker_practice/)

## 安装

```sh
# 删除旧的版本
yum remove docker \
                  docker-client \
                  docker-client-latest \
                  docker-common \
                  docker-latest \
                  docker-latest-logrotate \
                  docker-logrotate \
                  docker-engine

# 需要的安装包
yum install -y yum-utils

# 设置镜像仓库 下面为阿里云的
yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo  #默认是国外的

yum-config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo

# 更新yum软件包索引
yum makecache fast

# 安装docker 引擎
yum install docker-ce docker-ce-cli containerd.io

# 启动docker
systemctl start docker

docker version #查看版本是否安装成功

docker run hello-world #运行该镜像 如果没有将会拉去官方镜像

docker images # 查看已有镜像

# 卸载docker
# 卸载依赖
yum remove docker-ce docker-ce-cli containerd.io

#删除资源
sudo rm -rf /var/lib/docker
sudo rm -rf /var/lib/containerd
```

/var/liv/docker docker 在宿主机的默认工作路径

## 配置阿里云镜像加速

登录阿里云 找到容器镜像服务,按照下图命令复制粘贴即可

![](https://img.kuizuo.cn/image-20210527011655512.png)

## Docker 的命令

![](https://img.kuizuo.cn/v2-820aee2a33654099d87cdd2b7a1ce741_r.jpg)

```shell
docker info # 显示docker 系统信息
docker stats # 显示docker 所占用的资源
docker --help # 查看帮助
```

### 镜像命令

```sh
#查看本地主机上的镜像
docker images

[root@localhost ~]# docker images
REPOSITORY    TAG       IMAGE ID       CREATED       SIZE
hello-world   latest    d1165f221234   3 weeks ago   13.3kB

REPOSITORY 仓库源
TAG 标签 一般为版本号
IMAGE ID id
CREATED 创建时间
SIZE 大小

-a 显示全部
-q 只显示id

docker search 镜像名  # 搜索镜像
docker pull 镜像名:[TAG]  # 下载镜像
docker rmi 镜像ID # 删除镜像  -f 强制删除
docker rmi 镜像ID1 镜像ID2 镜像ID3 # 删除多个镜像 通过空格

docker rmi -f $(docker images -aq) # 删除全部镜像
```

### 容器命令

得先有了镜像才可创建容器

安装一个 centos 容器 docker pull centos

#### 启动容器

```shell
docker run [参数] image
# 参数说明
--name="名字" 指定容器名字
-d           后台方式运行
-it          交互方式运行,可进入容器查看内容
-p           指定容器的端口
-p           主机端口:容器端口
-v           宿主机路径:容器内路径   数据卷
```

#### 查看容器

```shell
docker ps 命令

-a    #所有+历史运行过的容器
-n=?  #最近创建的容器
-q    #只显示容器的编号

```

#### 退出容器

```shell
exit  #直接停止并退出
Ctrl + P + Q #不停止退出
```

#### 删除容器

注意 没有`i`

```shell
docker rm 容器id   #删除指定的容器
docker rm -f $(docker ps -aq) # 删除所有的容器
```

#### 启动和停止容器的操作

```shell
docker start 容器id
docker restart 容器id
docker stop 容器id
docker kill 容器id
```

#### 进入当前正在运行的容器

```shell
docker exec -it 容器id /bin/bash  #进入后开启新的终端 可在里面操作(常用)
docker attach 容器id # 不会启动新的进程 单单只是进入容器的终端
```

#### 后台启动容器

```
docker run -d 容器
docker run -d centos
docker ps
# 没有容器的数据   发现centos 停止了

```

常见的坑 docker 容器使用后台运行 就必须要有一个前台应用,否则将会自动停止
nginx 容器启动后 发现自己没有提供服务 就会立刻停止 **就是没有程序了**

#### 查看容器内的进程信息

```shell
docker top 容器id
```

#### 查看容器的元数据

```
docker inspect 容器id
```

#### 从容器内拷贝文件到宿主机上

```sh
docker cp 容器id:容器内路径 宿主机路径
```

### 自定义网络

```sh
docker network ls  #查看所有的docker 网络

docker network create --driver bridge mynet

创建容器通过 `--net`    默认为 --net bridge

docker network connect   # 连通网络
```

### 容器数据卷

一句话 容器的持久化和同步操作! 容器间 也是可以数据共享的

#### 使用数据卷

```sh
docker run -it -v 主机目录:容器目录
```

#### 指定路径挂载

注意 路径前有`/` 为绝对路径


#### 匿名挂载

只指定容器内的名字

```sh
docker run -d -P --name nginx -v /ect/nginx nginx

通过 docker volume ls 即可查看
为local  .....
```

#### 具名挂载

```sh
docker run -d -P --name nginx -v mynginx:/ect/nginx nginx

# mynginx 为卷名

docker volume inspect mynginx 可查看挂载位置
没指定目录 都是在 /var/lib/docker/volumes/卷名/_data

docker volume ls
local  mynginx
```

区别

```sh
-v 容器内路径  #匿名挂载
-v 卷名:容器内路径 #具名
-v /宿主机路径:容器内路径 #指定路径
```

拓展

```
-v 容器内路径:ro   rw
ro 表示只读 readonly 只可外部改变 只可宿主机改变
rw 可读写 readwirte  默认rw
```

#### 例子

安装Mysql

```sh
docker run -d -p 3307:3306 --privileged=true -v /data/mysql/log:/var/log/mysql -v /data/mysql/data:/var/lib/mysql -v /opt/docker/mysql/conf:/etc/mysql/conf.d -e MYSQL_ROOT_PASSWORD=123456 --name mysql mysql:5.7
```

安装Redis

```
docker run -d -p 6379:6379 --privileged=true -v /app/redis/redis.conf:/etc/redis/redis.conf -v /app/redis/data:/data -e MYSQL_ROOT_PASSWORD=123456 --name mysql mysql:5.7 redos-server /etc/redis/redis.conf
```



## DockerFile

![](https://img.kuizuo.cn/OIP.p3NmHHlewBvLwukFPGudFgHaFV.jpg)

所有命令大小写不敏感（但推荐大写）

构建镜像命令

```sh
docker build -t 自定镜像名 .
```

例：创建一个属于自己的 centos 镜像

```dockerfile
FROM cetnos
MAINTAINER kuizuo<911993023@qq.com>

ENV MYPATH /usr/local
WORKDIR $MYPATH

RUN yum -y install vim
RUN yum -y install net-tools

EXPOSE 80
CMD /bin/bash
```

通过 docker history 镜像 ID 可以查看 镜像的变更历史

CMD 和 ENTRYPOINT 区别

```
CMD  # 指定这个容器启动的时候要运行的命令,只有最后一个会生效,可被替代
ENTRYPOINT   # 指定这个容器启动的时候要运行的命令,可以追加命令 直接拼接的形
```

## 发布镜像

### Commit 镜像

```dockerfile
# 命令和git原理很像
docker commit -m="描述信息" -a="作者" 容器id 自定镜像名:[TAG]

即可在本地生成一个属于自己的镜像文件
```

### 发布

1、登录[Docker Hub](https://hub.docker.com/) 注册一个账号

2、docker login -u kuizuo

3、输入密码

```
[root@localhost ~]# docker login -u kuizuo
Password:
Error response from daemon: Get https://registry-1.docker.io/v2/: unauthorized: incorrect username or password
[root@localhost ~]# docker login -u kuizuo
Password:
WARNING! Your password will be stored unencrypted in /root/.docker/config.json.
Configure a credential helper to remove this warning. See
https://docs.docker.com/engine/reference/commandline/login/#credentials-store

Login Succeeded
```

4、docker push 镜像 ID 镜像名:[Tag]

5、有可能提交不上 需要修改下属 docker tag 镜像名

### 部署到阿里云容器服务

1、登录阿里云，在容器镜像服务 创建个人实例

2、创建命名空间，不然无法创建镜像仓库，且 只可创建 3 个

3、创建镜像仓库，然后选择本地仓库

4、点击管理可查看基本信息，操作指南写的非常详细
