---
id: docker-accesses-host-service
slug: /docker-accesses-host-service
title: Docker访问宿主机上服务
date: 2022-05-25
authors: kuizuo
tags: [docker]
keywords: [docker]
---

<!-- truncate -->

如果尝试过部署 docker 容器应用，并且该应用需要访问宿主机的服务，如 Mysql，Redis。会发现应用可能无法连接，其本质的原因的就是 docker 容器内的 localhost 与宿主机的 localhost 并不是同一个东西。所以连接地址不能用 localhost 和 127.0.0.1。

**宿主机是可以直接访问 docker 容器内的应用。**

## 解决办法

### 使用 host 模式（常用）

docker 运行容器时使用的[桥接](https://so.csdn.net/so/search?q=桥接&spm=1001.2101.3001.7020)模式(默认)，如果使用 host 模式就可以访问，所以需要将 docker 的网络模式设置为 host 模式。

通过`docker run` 启动容器时加入`–net=host` 参数，或在 compose 文件中指定`network_mode: “host”`，便可以 host 模式运行容器

该参数指定该容器使用 host 网络模式，因此也无需映射端口（不然会报警告）。

#### mac 和 windows

需要 env 配置中的 127.0.0.1 替换为**host.docker.internal**

#### linux

在启动 docker 时，加入如下语句

```bash
--add-host=host.docker.internal:host-gateway
```

而在 container 内，可以直接请求 host.docker.internal:PORT，来获取宿主机上提供的各种服务
如果使用了 Docker Compose，则应该将下面的句子加入 container 的声明中：

```yaml
extra_hosts:
  - 'host.docker.internal:host-gateway'
```

### 使用 docker0 网络的默认网关地址

在默认的 bridge 模式下，docker0 网络的默认网关即是宿主机。在 Linux（Windows）下，docker0 网络通常会分配一个 172.17.0.0/16 的网段，其网关通常为**172.17.0.1**；macOS 下的网段则为 192.168.65.0/24，网关为**192.168.65.1**。在容器中使用该 IP 地址即可访问宿主机上的各种服务。

需要注意的是，这种情况下，经由 docker0 网桥而来的流量不经过宿主机的本地回环，因此需要将宿主机上的应用（MySQL，Redis 等）配置为监听 0.0.0.0。

但此 IP 并不一定完全固定，可能会因系统及配置而发生变化，应用也需要更改。
