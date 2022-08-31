---
id: mongodb-note
slug: /skill/database/mongodb
title: MongoDB笔记
date: 2021-06-20
tags: [mongodb, database]
keywords: [mongodb, database]
---

## 安装

### Windows

官网下载[MongoDB Community Download](https://www.mongodb.com/try/download/community)

可安装 MongoDB Compass 的数据库管理工具

打开 bin/mongo.exe 即可连接 MongoDB

### Linux

推荐直接宝塔面板，然后在软件商店点击安装 MongoDB 即可

### Docker

[mongo (docker.com)](https://hub.docker.com/_/mongo)

```shell
docker pull mongo:latest

mkdir /home/mongo/ # 创建本地数据库文件夹

docker run -itd --name mongo --restart=always --privileged -p 27017:27017 -v /home/mongo/data:/data/db  -v /home/mongo/conf:/data/configdb  -v /home/mongo/logs:/data/log/ mongo:latest --config /data/configdb/mongod.conf --bind_ip_all
# -v 指定配置文件启动
# --bind_ip_all 允许所有IP访问
# ----restart=always  Docker服务重启容器也启动
# --privileged  拥有真正的root权限

docker exec -it mongo bash
# 进入容器

root@71351dc5b914:/# mongo
# 进入 mongo

# 后文有
```

### 配置远程连接

首先按照上面步骤创建用户，后续都是以这个用户来进行连接数据库

找到配置文件

windows `\bin\mongod.cfg`

linux `/etc/mongo/mongod.conf`

```
bind_ip = 0.0.0.0

security:
  authorization:enabled
# 注意 两个空
```

注意: mongodb Compass 有可能会连接不上提示**Authentication failed**,但使用代码即可。

配置文件如下

```
# 数据库文件存储位置
dbpath = /data/db/
# log文件存储位置
logpath = /data/log/mongodb/master/mongodb.log
# 使用追加的方式写日志
logappend = true
# 是否以守护进程方式运行
# fork    = true
# 端口号
port    = 27017
# 是否启用认证
auth  = true
# 设置oplog的大小(MB)
oplogSize=2048
```

- 开启防火墙
  systemctl start firewall

- 防火墙放端口

  firewall-cmd --zone=public --add-port=27010/tcp --permanent

- 重启防火墙

  firewall-cmd --reload

## 基本命令

```shell
# 创建数据库
use 数据库名

show databases

show users
```

### 增删改查

原生的 mongodb CRUD 命令没啥好说的，Nodejs 主要配合 Mongoose 来使用，这边就直接不列举了

### 索引

```js
// 创建索引
db.user.ensureIndex({"username":1},{"name":"usernameIndex"}) // 1是升序  一般用降序 可查最新的账号  第二个参数可指定索引名称

// 获取索引
db.user.getIndexes()

// 删除索引
db.user.dropIndex({"username":1})

// 唯一索引
db.user.ensureIndex({"userId":1},{"unique",true})
// 再次插入userId重复的文档 mongodb将会报错 提示插入重复键  同时有重复文档也无法创建唯一索引
```

### 账户权限配置管理

#### 1.创建用户

```shell
use admin

# root 超级管理员
db.createUser({ user:'admin',pwd:'123456',roles:[ { role:'root', db: 'admin'}]});
db.auth('admin', '123456')

# 创建有可读写权限的用户. 对于一个特定的数据库, 比如 my，添加用户 user1，角色：dbOwner
db.createUser({user:"user1",pwd:"pwd",roles:[{role:"dbOwner",db:"my"}]})
```

一些角色权限 命令

### 角色命令

```
show users   // 查看当前数据库下角色

db.updateUser("admin",pwd:"password")

db.auth("admin","password")

// 或者 直接通过Url 来连接
const url = 'mongodb://admin:a123456.@localhost:27027/';
```

### 聚合管道

```js
// $projext 限制字段
db.order.aggregate([
{$projext:{no:1,all_price:1}}
])

// $match 过滤文档 类似于find 方法中的参数
db.order.aggregate([
	{$projext:{no:1,all_price:1}},
    {$match:{"all_price":{$get:90}}
])

// $group 分组
db.order.aggregate([
	{
    	$group:{_id:"$order_id",total:{$sum: "$price"}}
	},
])

// 可加 $sort  $skip

// $lookup 表关联
db.order.aggregate([
	{
    	$lookup:{
            from:'order_item',
            localField:"order_id",
            foreignField:"order_id",
            as:"items"
        }
	},
])
```

## Mongoose

### 连接

```js
const mongoose = require('mongoose');
let url = 'mongodb://localhost:27017/kuizuo';
mongoose.connect(url, { useNewUrlParser: true }, function (err) {});
```

### 定义 Schema

```js
import * as mongoose from 'mongoose';

let UserSchema = mongoose.Schema({
  username: {
    type: String,
    trim: true,
    unique: true, // 唯一索引  index:true 是普通索引
  },
  password: String,
  age: {
    type: Number,
    get(params) {
      return params + '岁';
    }, // get不建议使用  因为不是获取的时候添加 而是实例化的时候取的时候添加
  },
  status: Number,
  headImg: {
    type: String,
    set(params) {
      if (!params.includes('https://') || !params.includes('http://')) {
        return 'http://' + params;
      }
      return params;
    },
  },
});
```

### 定义模型

```js
// let User = mongoose.model('User', UserSchema) // 首字母大写  默认users表
let User = mongoose.model('User', UserSchema, 'user'); // 指定user表

User.find({}, (err, doc) => {
  console.log(doc);
});

// 增加数据
// 实例化对象
let user = new User({
  username: 'kuizuo',
  password: 'a12345678',
});

user.save();
```

### 自定义封装方法(一般很少使用)

```js
// 静态方法 实在Schema上扩展
UserSchema.statics.findByUsername = function(username,cb){
    this.find({'username',username},function(err,data){
        cb(err,data)
    })
}

// 实例方法  没多大用
UserSchema.methods.print = function(){
	console.log("实例方法")
}
```

### 数据效验

```js
let UserSchema = mongoose.Schema({
  username: {
    type: String,
    trim: true,
   	require:true // 必须传入
  },
  password: String,
  mobile:{
  	match: /^1((34[0-8]\d{7})|((3[0-3|5-9])|(4[5-7|9])|(5[0-3|5-9])|(6[0-9])|(7[0-3|5-8])|(8[0-9])|(9[1|5|8|9]))\d{8})$/,
  },
  age: {
    type: Number,
	max: 200,
	min: 0
  },
  status: {
  	type:String,
  	default:"success",
  	enum:["success",'error] //用在String类型
  },
  headImg: {
    type: String,
    set(params) {
      if (!params.includes("https://") || !params.includes("http://")) {
        return 'http://' + params
      }
      return params
    }
  }
})
```

## Mongoose 命令

### 查询指定时间范围

```
let filter = {
	timestamp: {
	'$gte': 123456789,
	'$lte': 987654321,
	}
}
```

1. (>) 大于 - $gt
2. (<) 小于 - $lt
3. (>=) 大于等于 - $gte
4. (<= ) 小于等于 - $lte

如果时间日期格式是 ISO，则需用使用 ISODate 函数转为一下

```
ISODate("2020-01-01T00:00:00Z")
```

### 去除 mongodb \_\_v 字段

[去除 mongodb 下划线\_\_v 字段](https://blog.csdn.net/a1059526327/article/details/106893186)

去除\_\_v 字段，可以在定义 schema 规则的时候通过设置`versionKey:false`去除这个字段：

```js
var userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
      select: false,
    },
  },
  { versionKey: false },
);
```

如果在数据库中扔向保留这个字段，只是在查询的时候不想返回**v 字段，可以通过设置{ **v: 0}在返回结果中过滤掉这一字段

```js
UserModel.findOne({username, password}, {__v: 0}, function (err, user){
}
```

### 查询内嵌数组

原始数据如下

```json
{
    "_id" : ObjectId("5aab3460353df3bd352e0e15"),
    "username": "15212345678"
    "tags" : [
        {
            "name" : "前端",
        },
        {
            "name" : "后端",
        },
    ]
}
```

查询 username=15212345678 and tags.name="前端" （**不希望出现这个后端**）

想要的数据为

```json
{
    "_id" : ObjectId("5aab3460353df3bd352e0e15"),
    "username": "15212345678"
    "tags" : [
        {
            "name" : "前端",
        }
    ]
}
```

但通过 find 查询会将整个文档都给返回，这是我们不希望的，有两种方法可以实现

#### $elemMatch

```js
Model.find({ username: '15212345678', name: { $elemMatch: { name: '前端' } } });
```

要注意的是：**对于数组中只有一个返回元素，我们可以使用$elemMatch来查询，但是对于多个元素$elemMatch 是不适应。**

#### aggregation

[Aggregation Pipeline](https://docs.mongodb.com/manual/reference/operator/aggregation-pipeline/)

一共有三个参数

- $unwind: 将数组中的每一个元素转为每一条文档
  使用$unwind 可以将指定内嵌数组中的每个数据都被分解成一个文档，并且除了指定的值不同外，其他的值都是相同的
- $match: 简单的过滤文档，条件查询。query
- $project: 修改输入文档的结构，例如别名，字段显示  [mongoose聚合—$project](https://www.cnblogs.com/ellen-mylife/p/14794284.html)

例:

```json
Model.aggregate([{ "$unwind": "$tags" }, { "$match": { "tags.name": "前端" } }, { "$project": { "tags": 1 } }])
```

但显示的效果为

```json
{
    "_id" : ObjectId("5aab3460353df3bd352e0e15"),
    "username": "15212345678"
    "tags" : {
            "name" : "前端",
     }
}
```

tags 直接有**数组转为文档**了，因为添加了$unwind这个参数，将会拆分为多条数据，比如我不加$match 那么还将输出 tags 为后端单独一个文档，这肯定也不是想要的数据，就是想要这个 tags 为数组，那么有如下两种操作方式

#### $group

方法一：使用$unwind将tags数组打散,获取结果集后用$match 筛选符合条件的数据，最后使用$group 进行聚合获取最终结果集。

```json
db.getCollection("user").aggregate([
  { "$unwind": "$tagss" },
  { "$match": { "tags.name": "前端" } },
  {
    "$group": {
      "_id": "$uid",
      "username": { "$first": "$username" },
      "tags": { "$push": "$tags" }
    }
  }
])
```

不过要注意的是，要显示其他字段的话，可以通过$first来显示，如`“username”: { $first: "$username" }`

方法二：使用$match过滤符合条件的根文档结果集，然后使用$project 返回对应字段的同时，在 tags 数组中使用$filter 进行内部过滤，返回最终结果集

```
db.getCollection('user').aggregate(
  [
    { "$match": { }},
    {
      $project: {
        "uid": 1,
        "username": 1,
        "tags": {
          $filter: {
            input: "$tags",
            as: "item",
            cond: { $eq : ["$$item.name","前端"] }
          }
        }
      }
    }
  ]
)
```

相比 group 而言，filter 比较直接，但通过 group 可以直接统计对应的数量啥的，毕竟分组聚合才是关键精髓。

## 数据份与恢复

[MongoDB 备份与恢复](https://zhuanlan.zhihu.com/p/163255094)

### 备份

```
mongodump -h dbhost -d dbname -o dbdirectory
```

-h：MongoDB 所在服务器地址，例如：127.0.0.1，当然也可以指定端口号：127.0.0.1:27017

-d：需要备份的数据库实例，例如：test

-o：备份的数据存放位置，例如：c:\data\dump，当然该目录需要提前建立，在备份完成后，系统自动在 dump 目录下建立一个 test 目录，这个目录里面存放该数据库实例的备份数据。

--gzip：压缩格式 gzip

mongodump 命令可选参数列表如下所示：

| 语法                                              | 描述                           | 实例                                             |
| :------------------------------------------------ | :----------------------------- | :----------------------------------------------- |
| mongodump --host HOST_NAME --port PORT_NUMBER     | 该命令将备份所有 MongoDB 数据  | mongodump --host runoob.com --port 27017         |
| mongodump --dbpath DB_PATH --out BACKUP_DIRECTORY | 指定备份数据库位置             | mongodump --dbpath /data/db/ --out /data/backup/ |
| mongodump --collection COLLECTION --db DB_NAME    | 该命令将备份指定数据库的集合。 | mongodump --collection mycol --db test           |

例: 备份 test 数据库

```
mongodump  --port 27017  -u test -p 123456 --authenticationDatabase test -o back
```

### 恢复

mongorestore 命令脚本语法如下：

```
mongorestore -h <hostname><:port> -d dbname <path>
```

- --host <:port>, -h <:port>：MongoDB 所在服务器地址，默认为： localhost:27017

- --db , -d ：需要恢复的数据库实例，例如：test，当然这个名称也可以和备份时候的不一样，比如 test2

- --drop：恢复的时候，遇到重复值先删除当前数据，然后恢复备份的数据。就是说，恢复后，备份后添加修改的数据都会被删除，慎用哦！

- \<path\>：mongorestore 最后的一个参数，设置备份数据所在位置，例如：c:\data\dump\test。

  你不能同时指定 \<path\> 和 --dir 选项，--dir 也可以设置备份目录。

- --dir：指定备份的目录

  你不能同时指定 \<path\> 和 --dir 选项。

例:

```
mongorestore  --port 27017  -u test -p 123456 --authenticationDatabase test
```

### 将 mysql 中的数据导入 mongo

1、mysql 开启安全路径

`vim /etc/my.cnf`

```text
#添加以下配置
secure-file-priv=/tmp
```

重启数据库生效

```text
/etc/init.d/mysqld restart
```

2、mysql ⾃定义分隔符导出成 csv 格式

```text
select * from test.t100w limit 10 into outfile '/tmp/100w.csv' fields terminated by ',';
```

PS：mysql 导出 csv

fields terminated by ','　　　 ------字段间以,号分隔

optionally enclosed by '"'　　 ------字段用"号括起

escaped by '"' 　　　------字段中使用的转义符为"

lines terminated by '\r\n';　　------行以\r\n 结束

PS：mysql 导入 csv

```text
load data infile '/tmp/2.csv'
into table t1
fields terminated by ','  ;
```

3、在 mongodb 中导入备份

```text
mongoimport -u root -p root123 --port 27017 --authenticationDatabase admin -d test  -c t100w --type=csv -f id,num,k1,k2,dt --file  /tmp/100w.csv
```
