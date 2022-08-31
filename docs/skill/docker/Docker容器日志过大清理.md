---
id: docker-container-log-clean
slug: /docker-container-log-clean
title: Docker容器日志过大清理
date: 2021-10-16
authors: kuizuo
tags: [docker]
keywords: [docker]
---

<!-- truncate -->

在我以 docker 容器部署了 elasticsearch 服务后的 3 个月时间，发现硬盘会不断的增大，一开始时没在意，直到硬盘报黄，就像下图这样

![image-20211016180014693](https://img.kuizuo.cn/image-20211016180014693.png)

于是就准备找找是什么原因导致硬盘空间不断增大。

## linux 查找最大占用空间的文件

```sh
# 进入根目录
cd /
# 查看根目录下每个文件夹的大小
du -sh *
```

进入占用空间比较大的文件夹，再通过 `du -sh *` 找到最大的文件夹，如此反复便可找到最大

或使用下列命令（会稍微需要一些时间，建议先使用上面命令来缩小目录范围）

```sh
# Linux中查找当前目录下占用空间最大的前10个文件或文件夹
du -am | sort -nr | head -n 10
```

搜寻的结果如下，一眼就能看的出那个文件夹与文件

```
134938  .
125920  ./var
125315  ./var/lib
125229  ./var/lib/docker
94888   ./var/lib/docker/containers
94297   ./var/lib/docker/containers/f603a98f79874bca0e075ec1fcb0ec6866555832a4678631e7dffa7f34297281/f603a98f79874bca0e075ec1fcb0ec6866555832a4678631e7dffa7f34297281-json.log
94297   ./var/lib/docker/containers/f603a98f79874bca0e075ec1fcb0ec6866555832a4678631e7dffa7f34297281
30335   ./var/lib/docker/overlay2
27291   ./var/lib/docker/overlay2/f43f485f7707293cda3319786debbbdede5d940c7706c0c4b5464f57eeed7bdb
14012   ./var/lib/docker/overlay2/f43f485f7707293cda3319786debbbdede5d940c7706c0c4b5464f57eeed7bdb/merged
```

最终定位到文件夹`/var/lib/docker/containers`，输出当前文件夹下的文件大小

```
du -d1 -h /var/lib/docker/containers | sort -h
```

结果如下

```sh
[root@localhost /]# du -d1 -h /var/lib/docker/containers | sort -h
93G     /var/lib/docker/containers
93G     /var/lib/docker/containers/f603a98f79874bca0e075ec1fcb0ec6866555832a4678631e7dffa7f34297281
```

成功找到这个文件`f603a98f79874bca0e075ec1fcb0ec6866555832a4678631e7dffa7f34297281-json.log`，近 93GB（反正我是没敢尝试打开，生怕直接把服务器干宕机了）

### 问题

[docker](https://so.csdn.net/so/search?q=docker)容器日志导致主机磁盘空间满了。elasticsearch 的 log 很占用空间，完全可以清理掉了。

### 清理 Docker 容器日志

如果 docker 容器正在运行，那么使用 rm -rf 方式删除日志后，那么删除后会发现磁盘空间并没有释放。原因是在 Linux 或者 Unix 系统中，通过 rm -rf 或者文件管理器删除文件，将会从文件系统的目录结构上解除链接（unlink）。如果文件是被打开的（有一个进程正在使用），那么进程将仍然可以读取该文件，磁盘空间也一直被占用。删除后重启 docker。

#### 日志清理脚本 clean_docker_log.sh

```sh
#!/bin/sh
echo "======== start clean docker containers logs ========"

logs=$(find /var/lib/docker/containers/ -name *-json.log)

for log in $logs
        do
                echo "clean logs : $log"
                cat /dev/null > $log
        done

echo "======== end clean docker containers logs ========"

# chmod +x clean_docker_log.sh

# ./clean_docker_log.sh
```

### 设置 Docker 容器日志大小

上述方法，日志文件迟早又会涨回来。要从根本上解决问题，需要限制容器服务的日志大小上限。这个通过配置容器 docker-compose 的 max-size 选项来实现

```yaml
nginx:
  image: nginx:1.12.1
  restart: always
  logging:
    driver: “json-file”
    options:
      max-size: “5g”
```

### 全局设置

新建/etc/docker/daemon.json，若有就不用新建了。添加 log-dirver 和 log-opts 参数，样例如下：

```sh
# vim /etc/docker/daemon.json

{
  "log-driver":"json-file",
  "log-opts": {"max-size":"500m", "max-file":"3"}
}

```

max-size=500m，意味着一个容器日志大小上限是 500M，
max-file=3，意味着一个容器有三个日志，分别是 id+.json、id+1.json、id+2.json。

```sh
# 重启docker守护进程

systemctl daemon-reload

systemctl restart docker
```

> 参考文章: [Docker 容器日志占用空间过大解决办法](https://blog.csdn.net/gdsfga/article/details/90599131)
