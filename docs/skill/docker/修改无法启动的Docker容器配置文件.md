---
id: fix-docker-config-that-cannot-start-up
slug: /fix-docker-config-that-cannot-start-up
title: 修改无法启动的Docker容器配置文件
date: 2021-08-17
authors: kuizuo
tags: [docker, elasticsearch]
keywords: [docker, elasticsearch]
---

<!-- truncate -->

## 前因

事情是这样的

我想给我的 elasticsearch 扩充一下内存，默认配置的内存太少了，机器 32g，连 16g 都没占用上，有好几次的时候同时并发几千条服务就挂了。。。

于是，进入 elasticsearch 容器，找到`elasticsearch.yml`（注意这个文件）

![image-20210817142200704](https://img.kuizuo.cn/image-20210817142200704.png)

添加了下列两个参数

-Xms16g
-Xmx16g

然后重启容器，就发现容器怎么也启动不了，然后咋一看，配置文件搞错了，设置内存的应该是`jvm.options`这个配置文件

### 解决办法

所以目标很明确，只需要更改回原来配置文件即可正常启动。但容器只要一重启就会立马挂掉，都启动不了，又怎么通过`docker exec -it elasticsearch /bin/bash`进入容器，然后通过 vim 修改配置呢。

我当时的想法是这样的，容器一启动肯定不会立马挂掉，至少会有个几秒，我能不能通过一系列的命令进入容器然后立马修改文件，想法是挺好，可当 vim 编辑文件的，我又改怎么通过进入编辑，保存退出编辑。于是就果断放弃，翻看自己之前写过的 Docker 笔记 ，发现。有一个命令`docker cp 容器id:容器内路径 宿主机路径`从容器内拷贝文件到宿主机上，于是找到 elasticsearch 的配置文件路径`/usr/share/elasticsearch/config`，我的容器名字

```sh
docker cp elasticsearch:/usr/share/elasticsearch/config/elasticsearch.yml .
vi elasticsearch.yml
# 编辑文件
docker cp elasticsearch.yml :/usr/share/elasticsearch/config/elasticsearch.yml
docker start elasticsearch
```

然后重启 elasticsearch 容器即可正常运行

## 后果

回到最开始的目的，那么要如何更改 elasticsearch 内存呢

如果要新建一个容器的话 附带这个参数即可`-e ES_JAVA_OPTS="-Xms64m -Xmx512m"`

如果已经新建过容器的话，找到**jvm.options**这个文件

```sh
[root@localhost /]# find /var/lib/docker/ -name jvm.options
/var/lib/docker/overlay2/1f06b1e87d0fd473cc910d8689add0638f1ac36676d92f92dc03b17e65bf7dae/diff/usr/share/elasticsearch/config/jvm.options
/var/lib/docker/overlay2/d20c175dffdc80467dbce39d4a5bc6dc9f7ff239564a8ee1ac8c4bcfdd9a461e/merged/usr/share/elasticsearch/config/jvm.options
```

![image-20210817145633786](https://img.kuizuo.cn/image-20210817145633786.png)

如图，设置对应的内存大小即可，重启 elasticsearch 容器即可
