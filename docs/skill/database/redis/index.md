---
id: redis-note
slug: /skill/database/redis
title: Redis笔记
date: 2021-05-21
tags: [redis, database]
keywords: [redis, database]
---

[redis 中文官方网站](http://www.redis.cn/)

## 安装

官方推荐使用 Linux 去开发使用！

### window

下载地址：https://github.com/tporadowski/redis/releases

下载 **Redis-x64-xxx.zip**压缩包 解压为 redis

在 redis 目录下，打开 CMD 输入 或者双击运行 redis-server.exe

```shell
redis-server.exe redis.windows.conf
```

在打开一个输入

```shell
redis-cli.exe -h 127.0.0.1 -p 6379
```

即可连接

### Linux

[redis 下载](http://redis.io/download)

`redis-6.0.8.tar.gz`

```bash
# wget http://download.redis.io/releases/redis-6.0.8.tar.gz
# tar xzf redis-6.0.8.tar.gz
# cd redis-6.0.8

# 安装gcc-c++ 编译
yum instatll gcc-c++
# make
```

执行完 **make** 命令后，redis-6.0.8 的 **src** 目录下会出现编译后的 redis 服务程序 redis-server，还有用于测试的客户端程序 redis-cli

下面启动 redis 服务

```bash
# cd src
# ./redis-server
```

注意这种方式启动 redis 使用的是默认配置。也可以通过启动参数告诉 redis 使用指定配置文件使用下面命令启动。

```bash
# cd src
# ./redis-server ../redis.conf
```

redis 默认安装路径 `/usr/local/bin`

### Docker

#### 拉取镜像

```shell
docker pull redis
```

#### 启动 Redis

```shell
docker run -d  -v $PWD/data:/data --name redis -p 6379:6379 redis redis-server --requirepass "123456" --appendonly yes
```

启动命令说明：

- `$PWD/data:/data` : 映射 redis 的 data 目录到当前目录下的 data 目录
- `--requirepass` : 是设置 redis 的密码
- `--appendonly yes` : 启用持久化存储

例如：

```shell
docker run -d  -v /home/app/redis/data:/data --name redis -p 6379:6379 redis  redis-server --requirepass "123456" --appendonly yes
```

如果需要使用配置文件，则需要做个文件映射；注意所在目录下必须要有 redis.conf 这个文件，否则将启动失败。

```shell
docker run -d  -v /home/app/redis/data:/data  -v /home/app/redis/conf:/usr/local/etc/redis --name redis -p 6379:6379 redis redis-server /usr/local/etc/redis/redis.conf
```

> redis 的这个配置文件可以到官方的这个地址上去获取 http://download.redis.io/redis-stable

更多: [Docker 上安装 Redis](https://www.cnblogs.com/vchar/p/14347260.html)

## 基本命令

[Redis 命令中心（Redis commands）](http://www.redis.cn/commands.html)

Redis 不区分大小写 一般推荐大写(与 Mysql 一样)

```bash
set key value

get key

keys * # 查看所有key

EXISTS key # 判断key 是否存在
type key # 查看key的value类型

EXPIRE key second # 设置key的过期时间,单位是秒

ttl key # 查看当前key 的剩余时间
```

## 五大数据类型

Redis 支持五种数据类型：string（字符串），hash（哈希），list（列表），set（集合）及 zset(sorted set：有序集合)。

### String

```
APPEND key '123' # 给key后面追加字符串123 如果key不存在 则为set 返回字符串长度

STRLEN key # 获取字符串长度

incr key # 自增1

decr key # 自减1

INCRBY key 10 # 递增10 指定增量

DECRBY key 10 # 递减10

GETRANGE key 0 3 # 截取字符串 0-3 包括3
GETRANGE key 0 -1 # 截取所有字符串

SETRANGE key 1 xxx # 替换指定位置的字符串

###########################################################################
setex (set with expire) # 设置过期时间
setnx (set if not exist) # 不存在在设置 (分布式锁中会常常使用)

setex key3 30 'hello' # 设置key3的为hello,30秒后过期

###########################################################################
mset mget msetex # 批量设置与批量获取

mset k1 v1 k2 v2 k3 v3

msetex k1 v1 k4 v4 # 原子性的操作 要么一起成功 要么一起失败

getset key value # 先取后设置 不存在则返回nil 如果存在,则获取,并赋为新值
############################################################################
# 对象
set user:1 {name:kuizuo,age:20} # 设置user为一个对象
# or
set user:1:name kuizuo
# user:{id}:{filed} value

get user:1
# or
get user:1:name

```

String 类似的使用场景: value 除了是字符串还可以是数字 或者对象

### List

redis 里 List 可以充当栈,队列,阻塞队列

**所有 list 命令用 l 开头**

```bash
LPUSH list value # 将value 将一个值或多个值插入列表头部(左)

RPUSH list value # 将value 将一个值或多个值插入列表底部(右)

LRANGE list 0 -1 # 获取所有list元素

LPOP list # 移除list的第一个元素(左)

RPOP list # 移除list的最后一个元素(右)

Lindex list 1 # 通过下标获取list中的某一个值

Lset list 0 item # 如果不存在列表 去更新就会报错

Llen list # 取列表的长度

Lrem list 1 one # 移除指定的值 例:移除一个为one的

Ltrim list 1 2 # 截取1-2 包括2

Linsert list before "world" "new" # 在world 前面插入new 后面则用after


rpoplpush list1 list2 # 移除列表最后一个元素,将他移动到新的列表
```

列表实际上就是一个链表

可以实现消息队列 (Lpush Rpop),栈(Lpush Lpop)

### Set

set 中的值是无法重复的，无序不重复集合

**set 命令用 s 开头**

```bash
sadd myset "hello" # set集合中添加元素

scard myset # 获取set集合中的内容元素个数

smembers myset # 查看指定set的所有值

sismember myset hello # 判断某一个值是不是在set集合中

SRANDMEMBER myset # 随机抽选出一个元素
SRANDMEMBER myset 2 # 随机抽选出指定个数元素
#####################################################################
# 获取set中的差集
SDIFF set1 set2

# 获取set中的交集
SINTER set1 set2

# 获取set中的并集
SUNION set1 set2
```

例如：共同好友就可以使用 set 交集来实现

### Hash

Map 集合，key-map(key-value)

**set 命令用 h 开头**

```bash
hset myhash field1 kuizuo

hget myhash field1

hgetall myhash

hdel myhash

hlen myhash # 获取hash表的字段数量

HEXISTS myhash field1 # 判断hash中 指定字段是否存在

Hkeys myhash # 只获得所有field

Hvals myhash # 只获得所有value
```

hash 可变更数据 比如 user 信息,更适合对象的存储

### Zset

有序集合，在 set 的基础上增加了一个值 score

**zset 命令用 z 开头**

```bash
zadd myset 1 one

zadd myset 2 two 3 three

# ZRANGEBYSCORE key min max 一定要从小到大
ZRANGEBYSCORE myset -inf +inf # 根据score排序

ZREVERANGE myset 0 -1 # 从大到小进行排序!

Zrem myset item # 移除有序集合中的指定元素

Zcard myset # 获取有序集合中元素的个数


```

案例:set 排序 班级成绩表，工资表排序

普通消息 1 重要消息 2 带权重进行判断

排行榜应用实现，取 TOP N

## 三种特殊数据类型

### geospatial

地址位置，**geospatial 命令用 geo 开头**

**GEO 底层的实现原理就是 Zset,所以可以使用 Zset 命令来操作 Geo!**

应用: 推算地理位置的信息，两地之间的距离，方圆几里的人

```bash
# 规则: 两极无法直接添加,一般都是直接下载城市数据,直接通过程序一次性读入
# 参数: key (经度，纬度、名称) 切记不可反！ 经纬度
# 有效经度-180度到180度 有效纬度-85.05112878到85.05112878
GEOADD china:city 116.40 39.90 beijin # 设置北京的经纬度

GEOPOS china:city beijing # 获取北京的经纬度

GEODIST china:city beijing shanghai unit # 获取两地之间的距离 默认单位m

GEORADIS china:city 110 30 1000 km # 以110,30 这个点范围1000km的 地理位置
GEORADIS china:city 110 30 500 km withdist withcoord count 10 # 以110,30 这个点范围500km的 获取10个 带直线距离和经纬度

GEORADIUSBYMEMBER chaina:city beijing 1000m # 以北京周围1000km的 地理位置

GEOHASH china:city beijing # 将二维的地址位置转为一位11位字符串,如果两个字符串越接近,则距离越近

ZRANGE chaina:city 0 -1 # 查看地图中全部元素

ZREM chaina:city beijing # 移除指定元素
```

### Hyperloglog

Redis Hyperloglog 基数统计的算法

基数(不重复的元素)，会有误差！0.81 的错误率，但使用场景是可以接受的

统计网页的 UV （一个人访问一个网站多次，但是还是算作一个人），传统的方式，用 set 保存用户的 id，然后统计 set 中的元素数量来作为标准判断。

**Hyperloglog 命令 使用 PF 开头**

```bash
PFadd mykey1 a b c d e f g h i j
PFadd mykey2 i j k l m n o

PFMERGE mykey3 mykey1 mykey2 # 获取并集 并生成新的组

PFCOUNT mykey # 获取元素的数量
```

允许容错,一定可以使用 Hyperloglog

不允许容错,就使用 set 与自己的数据类型即可

### Bitmaps

位存储

统计用户信息，活跃，不活跃；登录，不登录，打卡；两个状态的都可以使用 Bitmaps

Bitmaps 位图,数据结构，都是操作二进制为来进行记录，就只有 0 和 1 两个状态！

```
# 记录周一到周日的打卡
setbit sign 0 1
setbit sign 1 1
setbit sign 2 1
setbit sign 3 1
setbit sign 4 1
setbit sign 5 0
setbit sign 6 0

# 查看某一天是否有打开
getbit sign 3

# 统计打卡的天数
bitcount sign
```

## 事务

Redis 单条命令式保存原子性的，但是事务不保证原子性!

Redis 事务本质： 一组命令的集合！一个事务中的所有命令都会被序列化，会安卓顺序执行

一次性、顺序性、排他性！执行一些列的命令！

Redis 事务没有隔离级别的概念！

所有命令在事务中并没有直接呗执行！而只有发起执行命令的时候才会执行！Exec

- 开始事务（multi）
- 命令入队（...）
- 执行事务（exec）

```
multi

set k1 v1
set k2 v2

get k1

exec  # 执行事务

DISCARD # 取消事务 事务队列中的命令都不会被执行

# 代码有问题，命令有错，事务中所有命令都不会被执行
# 运行中异常，执行其他命令正常，错误命令抛出异常
```

### 监控 Watch

悲观锁：很悲观，认为什么时候都会出问题，无论做什么都会加锁

乐观锁：很乐观，认为什么时候都不会出问题，所以不会上锁！更新数据的时候判断一下，在此期间是否有人修改过该数据

```
set money 100
set out 0

watch money

multi

DECRBY money 20
InCRBY money 20

# 如果这时用户充钱了 那么exec就无法执行
exec

# 解除监控，并重新监控最新的值
unwatch money
watch money

```

## Redis.conf

配置文件 unit 单位对大小写不敏感

##### 网络

```
bind 127.0.0.1 # 绑定的IP

protected-mode yes # 保护模式

port 6379 # 端口设置
```

##### GENERAL 通用

```
daemonize yes # 以守护进程方式的运行,默认是no,需自己开启yes

pidfile /var/run/redis_6379.pid # 以后台方式运行,就需要指定一个pid文件

# Specify the server verbosity level.
# This can be one of:
# debug (a lot of information, useful for development/testing)
# verbose (many rarely useful info, but not a mess like the debug level)
# notice (moderately verbose, what you want in production probably)
# warning (only very important / critical messages are logged)
loglevel notice

logfile # 日志文件位置名

database 16 # 数据库数量 默认16个
alaways-show-logo yes # 是否总是显示LOGO
```

##### 快照

持久化,在规定的时间内,执行了多少次操作,则会持久化到文件 .rdb .aof

```
stop-writes-on-bgsave-error yessave 900 1 # 在900s内,如果至少有一个key修改 则持久化操作
save 300 10 # 在300s内,如果至少有10个key进行修改 则持久化操作
save 60 10000

stop-writes-on-bgsave-error yes # 持久化如果出错 是否继续工作

rdbcompression yes # 是否压缩rdb文件,会消耗一些cpu资源
rdbchecksum yes # 保存rdb文件的时候,是否效验

dir ./ # rdb保存的目录

dbfilename dump.rdb # 保存的文件名
```

##### REPLICATION 主从复制

```
slaveof <masterip> <masterport> # 设置主机的端口和ip
```

##### SECURITY 密码

requirepass 密码

```
config get requirepass

config set requirepass "123456"

auth 123456
```

##### CLIENTS 客户端

```
maxclients 10000  # 默认客户端连接数

maxmemory <bytes> # redis 配置最大的内存容量

maxmemory-policy noeviction # 内存达到上限后的处理策略 # 移除一些过期的key

noeviction: 不删除策略, 达到最大内存限制时, 如果需要更多内存, 直接返回错误信息。（默认值）
allkeys-lru: 所有key通用; 优先删除最近最少使用(less recently used ,LRU) 的 key。
volatile-lru: 只限于设置了 expire 的部分; 优先删除最近最少使用(less recently used ,LRU) 的 key。
allkeys-random: 所有key通用; 随机删除一部分 key。
volatile-random: 只限于设置了 expire 的部分; 随机删除一部分 key。
volatile-ttl: 只限于设置了 expire 的部分; 优先删除剩余时间(time to live,TTL) 短的key。
```

##### APPEND ONLY MODE aof 配置

```
appendonly no # 默认不开启aof模式,默认使用rdb方式持久化,在大部分情况,rdb够用
appendfilename "appendonly.aof"  # 持久化文件名

# appendfsync always  # 每次修改都会 sync 消耗性能
appendfsync everysec   # 美妙执行一次 sync,可能会丢失这1s的数据!
# appendfsync no # 不执行sync,这个时候操作系统自己同步数据,速度最快

```

## Redis 持久化

redis 是内存数据库,单如果不将内存中的数据库状态保存的磁盘,一旦服务器进程退出,服务器中的数据库状态也会丢失,所以 redis 提供了持久化的功能

### RDB(Redis Database)

在指定的时间间隔内将内存中的数据集快照写入磁盘,也就是 Snapshot 快照,恢复时直接将快照文件读到内存

Redis 会单独创建 ( fork )一个子进程来进行持久化，会先将数据写入到一个临时文件中，待持久化过程都结束了，再用这个临时文件替换上次持久化好的文件。整个过程中，主进程是不进行任何 IO 操作的。这就确保了极高的性能。如果需要进行大规模数据的恢复，且对于数据恢复的完整性不是非常敏感，那 RDB 方式要比 AOF 方式更加的高效。RDB 的缺点是最后一次持久化后的数据可能丢失。我们默认的就是 RDB，一般情况下不需要修改这个配置!

**rdb 保存的文件是 dump.rdb**

dbfilename dump.rdb

#### 触发机制

1、save 的规则满足的情况下，会自动触发 rdb 规则

2、执行 flushall 命令，也会触发我们的 rdb 规则!

3、退出 redis，也会产生 rdb 文件!

就会自动生成一个 dump.rdb，有时候还有备份一份

#### 恢复 rdb 文件

只需要将 rdb 文件放在 redis 启动目录下就可以了,redis 启动的时候就会自动检查 dump.rdb 文件

```
config get dir
"dir"
"/usr/local/bin" # 如果在这个目录下存在dump.rdb 启动就会自动恢复其中的数据
```

优点:

1、适合大规模的数据恢复

2、对数据的完整性要求不高

缺点：

1、需要一定的时间间隔进程操作，如果 redis 意外宕机了，这个最后一次修改数据就没有了

2、fork 进程的时候，会占用一定的内存空间

### AOF（Append Only File）

将我们的所有命令都记录下来，history，恢复的时候就把这个文件内的命令全部在执行一遍

默认是不开启的，我们需要手动进行配置!我们只需要将 appendonly 改为 yes 就开启了 aof !重启

redis 就可以生效了

如果这个 aof 文件有错误，这时候 redis 是启动不起来的，我们需要修复这个 aof 文件，redis 给我们提供了一个工具 redis-check-aof --fix

优点

可指定修改都同步还是每秒都同步，文件完整性会更好

缺点:

相对于数据文件，aof 远远大于 rdb，修复的速度也不如 rdb

Aof 的运行效率也要比 rdb 慢。

### 小结

只做缓存，如果你只希望你的数据在服务器运行的时候存在，也可以不使用任何持久化

## Redis 发布订阅

Redis 发布订阅(publsub)是一种消息通信模式 ∶ 发送者(pub)发送消息，订阅者(sub)接收消息。Redis 客户端可以订阅任意数量的频道。
订阅/发布消息图︰

第一个：消息发布者，第二个频道（消息队列），第三个：消息订阅者

![查看源图像](http://cdn.kuizuo.cn/blogR50ea35ec36a3e4ea16cb132637477df0)

### 测试

订阅端

```
SUBSCRIBE kuizuo # 创建频道



```

发送端

```
PUBLISH kuizuo ‘hello‘


```

### 原理

Redis 是使用 C 实现的，通过分析 Redis 源码里的 pubsub.c 文件，了解发布和订阅机制的底层实现，
籍此加深对 Redis 的理解。
Redis 通过 PUBLISH、SUBSCRIBE 和 PSUBSCRIBE 等命令实现发布和订阅功能。
微信 ∶
通过 SUBSCRIBE 命令订阅某频道后，redis-server 里维护了一个字典，字典的键就是一个个频道!
，而字典的值则是一个链表，
链表中保存了所有订阅这个 channel 的客户端。SUBSCRIBE 命令的关键，就是将客户端添加到给定
channel 的订阅链表中。
通过 PUBLSH 命令向订阅者发送消息，redis-server 会使用给定的频道作为键，在它所维护的 channel 字典中查找记录了订阅这个频道的所有客户端的链表，遍历这个链表，将消息发布给所有订阅者。
Pub/Sub 从字面上理解就是发布( Publish)与订阅( Subscribe )，在 Redis 中，你可以设定对某一个 key 值进行消息发布及消息订阅，当一个 key 值上进行了消息发布后，所有订阅它的客户端都会收到相应的消息。这一功能最明显的用法就是用作实时消息系统，比如普通的即时聊天，群聊等功能。

使用场景：

1、实时消息系统，公告

2、实时聊天（将频道当做聊天室，将信息回显给所有人）

3、订阅，关注系统都是可以的

## Redis 主从复制

### 概念

主从复制，是指将一台 Redis 服务器的数据，复制到其他的 Redis 服务器。前者称为主节点(master/leader)，后者称为从节点(slave/follower);数据的复制是单向的，只能由主节点到从节点。Master 以写为主，Slave 以读为主。
默认情况下，每台 Redis 服务器都是主节点;且一个主节点可以有多个从节点(或没有从节点)，但一个从节点只能有一个主节点。

### 主从复制的作用主要包括︰

1、数据冗余 ∶ 主从复制实现了数据的热备份，是持久化之外的一种数据冗余方式。
2、故障恢复︰当主节点出现问题时，可以由从节点提供服务，实现快速的故障恢复;实际上是一种服务的冗余。
3、负载均衡︰在主从复制的基础上，配合读写分离，可以由主节点提供写服务，由从节点提供读服务（即写 Redis 数据时应用连接主节点，读 Redis 数据时应用连接从节点），分担服务器负载;尤其是在写少读多的场景下，通过多个从节点分担读负载，可以大大提高 Redis 服务器的并发量。
4、高可用基石 ∶ 除了上述作用以外，主从复制还是哨兵和集群能够实施的基础，因此说主从复制是 Redis 高可用的基础。

一般来说，要将 Redis 运用于工程项目中，只使用一台 Redis 是万万不能的

原因如下︰
1、从结构上，单个 Redis 服务器会发生单点故障，并且一台服务器需要处理所有的请求负载，压力较大;
2、从容量上，单个 Redis 服务器内存容量有限，就算一台 Redis 服务器内存容量为 256G，也不能将所有内存用作 Redis 存储内存，一般来说，**单台 Redis 最大使用内存不应该超过 20G。**

主从复制，读写分离！80%的情况下都是在进行读操作，就可以减缓服务器压力，架构中经常使用，一主二从

### 环境配置

```
redis:0>info replication  # 查看当前库信息
"# Replication
role:master  # 角色
connected_slaves:0 # 没有从机
master_replid:d6950e2fdb86b591f42e8725279034303e8cb6ee
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

```

需要修改 配置文件

端口 pid 名字 log 文件名 dump.rdb 名

### 一主二从

默认情况下，每台 Redis 服务器都是主节点;我们一般情况下只用配置从机就好了!认老大!一主（ 79)二从( 80，81 )

```
SLAVEOF 127.0.0.1 6379 # 找谁为主机
```

**主机可以写，从机不能写只能读！**主机中的所有数据都会被从机保存

主机断开连接，从机依旧可以连接到主机，并且主机回来，从机依旧可以直接获取数据

从机重新连接会主机，主机的任何操作立马同步到从机上

### 复制原理

slave 启动成功连接到 master 后会发送一个 sync 命令
Master 接到命令，启动后台的存盘进程，同时收集所有接收到的用于修改数据集命令，在后台进程执行完毕之后，**master 将传送整个数据文件到 slave，并完成一次完全同步。**

全量复制：slave 服务在接收到数据库文件数据后，将其存盘并加载到内存中。

增量复制：Master 继续将新的所有收集到的修改命令依次传给 slave，完成同步但是只要是重新连接 master，一次完全同步（全量复制)将被自动执行

### 层层链路

上一个 M 链接下一个 S

## 哨兵模式

[Redis 哨兵（Sentinel）模式](https://www.jianshu.com/p/06ab9daf921d)

### 概述

如果主机宕机了，从机要当主机，通过命令`SLAVEOF no one` 从机变主机，但如果这时候主机恢复了，那么就需要重新配置了，十分麻烦

主从切换技术的方法是 ∶ 当主服务器宕机后，需要手动把一台从服务器切换为主服务器，这就需要人工干预，费事费力，还会造成一段时间内服务不可用。这不是一种推荐的方式，更多时候，我们优先考虑哨兵模式。Redis 从 2.8 开始正式提供了 Sentinel (哨兵）架构来解决这个问题。

后台能够监控主机是否故障，如果故障了根据投票数自动将从机变为主机

### 实现

哨兵模式是一种特殊的模式，首先 Redis 提供了哨兵的命令，哨兵是一个独立的进程，作为进程，它会独立运行。其原理是**哨兵通过发送命令，等待 Redis 服务器响应，从而监控运行的多个 Redis 实例。**

![img](http://cdn.kuizuo.cn/blog11320039-57a77ca2757d0924.png)

### 配置

1、哨兵配置文件 sentinel.conf

```
sentinel monitor myredis 127.0.0.1 6379 1
```

后面的这个数字 1，代表主机挂了，slave 投票看让谁当主机，票数多的就会成为主机

2、启动哨兵

```
redis-sentinel config/sentinel.conf
```

3、主机挂了，从机当主机了，但是如果原主机恢复了，也只能乖乖当新主机的从机

优点:
1、哨兵集群，基于主从复制模式，所有的主从配置优点，它全有

2、主从可以切换，故障可以转移，系统的可用性就会更好

3、哨兵模式就是主从模式的升级，手动到自动，更加健壮

缺点:

1、Redis 不好啊在线扩容的，集群容量一旦到达上限，在线扩容就十分麻烦

2、实现哨兵模式的配置其实是很麻烦的，里面有很多选择

## Redis 缓存穿透和雪崩

**服务器高可用的问题**

Redis 缓存的使用，极大的提升了应用程序的性能和效率，特别是数据查询方面。但同时，它也带来了一些问题。其中，最要害的问题，就是数据的一致性问题，从严格意义上讲，这个问题无解。如果对数据的一致性要求很高，那么就不能使用缓存。
另外的一些典型问题就是，缓存穿透、缓存雪崩和缓存击穿。目前，业界也都有比较流行的解决方案。

### 缓存穿透

#### 概念

缓存查不到，导致数据都查数据库

缓存穿透的概念很简单，用户想要查询一个数据，发现 redis 内存数据库没有，也就是缓存没有命中，于是向持久层数据库查询。发现也没有，于是本次查询失败。当用户很多的时候，缓存都没有命中（秒杀!），于是都去请求了持久层数据库。这会给持久层数据库造成很大的压力，这时候就相当于出现了缓存穿透。|

#### 解决方案

##### 布隆过滤器

布隆过滤器是一种数据结构，对所有可能查询的参数以 hash 形式存储，在控制层先进行校验，不符合则丢弃，从而避免了对底层存储系统的查询压力

##### 缓存空对象

当存储层不命中后，即使返回的空对象也将其缓存起来，同时会设置一个过期时间，之后再访问这个数据将会从缓存中获取，保护了后端数据源;

但是这种方法会存在两个问题:
1、如果空值能够被缓存起来，这就意味着缓存需要更多的空间存储更多的键，因为这当中可能会有很多的空值的键;
2、即使对空值设置了过期时间，还是会存在缓存层和存储层的数据会有一段时间窗口的不一致，这对于需要保持一致性的业务会有影响。

### 缓存击穿

#### 概述

全都查缓存，此时缓存恰好过期，导致量过大

这里需要注意和缓存击穿的区别，缓存击穿，是指一个 key 非常热点，在不停的扛着大并发，大并发集中对这一个点进行访问，当这个 key 在失效的瞬间，持续的大并发就穿破缓存，直接请求数据库，就像在一个屏障上凿开了一个洞。
当某个 key 在过期的瞬间，有大量的请求并发访问，这类数据一般是热点数据，由于缓存过期
，会同时访问数据库来查询最新数
据，并且回写缓存，会导使数据库瞬间压力过大。

#### 解决方案

##### 设置热点数据永不过期

从缓存层面来看，没有设置过期时间，所以不会出现热点 key 过期后产生的问题。

##### 加互斥锁

分布式锁 ∶ 使用分布式锁，保证对于每个 key 同时只有一个线程去查询后端服务，其他线程没有获得分布式锁的权限，因此只需要等待即可。这种方式将高并发的压力转移到了分布式锁，因此对分布式锁的考验很大。

### 缓存雪崩

#### 概述

指在某一个时间段，缓存集中过期失效。Redis 宕机!

产生雪崩的原因之一，比如在写本文的时候，马上就要到双十二零点，很快就会迎来一波抢购，这波商品时间比较集中的放入了缓存，假设缓存一个小时。那么到了凌晨一点钟的时候，这批商品的缓存就都过期了。而对这批商品的访问查询，都落到了数据库上，对于数据库而言，就会产生周期性的压力波峰。于是所有的请求都会达到存储层，存储层的调用量会暴增，造成存储层也会挂掉的情况。

### 基本解决方案

redis 高可用
这个思想的含义是，既然 redis 有可能挂掉，那我多增设几台 redis，这样一台挂掉之后其他的还可以继续工作，其实就是搭建的集群。（异地多活!)
限流降级（在 SpringCloud 讲解过!)
这个解决方案的思想是，在缓存失效后，通过加锁或者队列来控制读数据库写缓存的线程数量。比如对某个 key 只允许一个线程查询数据和写缓存，其他线程等待。
数据预热
数据加热的含义就是在正式部署之前，我先把可能的数据先预先访问一遍，这样部分可能大量访问的数据就会加载到缓存中。在即将发生大并发访问前手动触发加载缓存不同的 key，设置不同的过期时间，让缓存失效的时间点尽量均匀。
