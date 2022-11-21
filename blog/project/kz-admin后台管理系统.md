---
slug: kz-admin
title: kz-admin后台管理系统
date: 2022-05-08
authors: kuizuo
tags: [project, admin, vue, nest]
keywords: [project, admin, vue, nest]
description: 基于 NestJs + TypeScript + TypeORM + Redis + MySql + Vben Admin 编写的一款前后端分离的权限管理系统
image: /img/project/kz-admin.png
---

当时初学 Web 开发的时候，除了写一个网页博客外，第二个选择无非就是一个后台管理系统，可以应用于多种需要数据管理类项目中。

基于**NestJs + TypeScript + TypeORM + Redis + MySql + Vben Admin**编写的一款前后端分离的权限管理系统

演示地址：[KzAdmin](https://admin.kuizuo.cn) 管理员账号：admin 密码：123456

<!-- truncate -->

![image-20220505171231754](https://img.kuizuo.cn/image-20220505171231754.png)

## 前端

**基于[Vben Admin](https://vvbin.cn/doc-next/)开发，使用 Vue3、Vite、TypeScript 等最新技术栈，内置常用功能组件、权限验证、动态路由。**

仓库地址：https://github.com/kuizuo/kz-vue-admin

### [项目结构](https://vvbin.cn/doc-next/guide/#%E7%9B%AE%E5%BD%95%E8%AF%B4%E6%98%8E)

```bash
├── build # 打包脚本相关
│   ├── config # 配置文件
│   ├── generate # 生成器
│   ├── script # 脚本
│   └── vite # vite配置
├── mock # mock文件夹
├── public # 公共静态资源目录
├── src # 主目录
│   ├── api # 接口文件
│   ├── assets # 资源文件
│   │   ├── icons # icon sprite 图标文件夹
│   │   ├── images # 项目存放图片的文件夹
│   │   └── svg # 项目存放svg图片的文件夹
│   ├── components # 公共组件
│   ├── design # 样式文件
│   ├── directives # 指令
│   ├── enums # 枚举/常量
│   ├── hooks # hook
│   │   ├── component # 组件相关hook
│   │   ├── core # 基础hook
│   │   ├── event # 事件相关hook
│   │   ├── setting # 配置相关hook
│   │   └── web # web相关hook
│   ├── layouts # 布局文件
│   │   ├── default # 默认布局
│   │   ├── iframe # iframe布局
│   │   └── page # 页面布局
│   ├── locales # 多语言
│   ├── logics # 逻辑
│   ├── main.ts # 主入口
│   ├── router # 路由配置
│   ├── settings # 项目配置
│   │   ├── componentSetting.ts # 组件配置
│   │   ├── designSetting.ts # 样式配置
│   │   ├── encryptionSetting.ts # 加密配置
│   │   ├── localeSetting.ts # 多语言配置
│   │   ├── projectSetting.ts # 项目配置
│   │   └── siteSetting.ts # 站点配置
│   ├── store # 数据仓库
│   ├── utils # 工具类
│   └── views # 页面
├── test # 测试
│   └── server # 测试用到的服务
│       ├── api # 测试服务器
│       ├── upload # 测试上传服务器
│       └── websocket # 测试ws服务器
├── types # 类型文件
├── vite.config.ts # vite配置文件
└── windi.config.ts # windcss配置文件
```

### 启动项目

建议使用 pnpm 包管理器来管理 node 项目，使用`npm install -g pnpm`即可安装。

```bash
pnpm install

pnpm run dev
```

运行结果

```bash
  vite v2.9.5 dev server running at:

  > Network:  https://192.168.184.1:3100/
  > Local:    https://localhost:3100/

  ready in 5057ms.
```

> 注: 开发环境下首次载入项目会稍慢(Vite 在动态解析依赖)

更多关于前端项目规范可直接参考 [Vben Admin 文档 ](https://vvbin.cn/doc-next/guide/introduction.html)，非常详细了。

## 后端

**基于 NestJs + TypeScript + TypeORM + Redis + MySql 编写的前后端分离权限管理系统**

仓库地址：https://github.com/kuizuo/kz-nest-admin

### [项目结构](https://blog.si-yee.com/sf-admin-cli/nest/usage.html#%E7%9B%AE%E5%BD%95%E7%BB%93%E6%9E%84%E8%AF%B4%E6%98%8E)

```bash
|─setup-swagger.ts # Swaager文档配置
|─main.ts # 主入口
|─config # 配置文件
|─shared
| |─redis # redisModule
| | |─redis.module.ts
| | |─redis.interface.ts
| | |─redis.constants.ts
| |─shared.module.ts
| |─services # 全局通用Provider
|─app.module.ts
|─mission
| |─mission.module.ts
| |─mission.decorator.ts # 任务装饰器，所有任务都需要定义该装饰器，否则无法运行
| |─jobs # 后台定时任务定义
|─common # 系统通用定义
| |─dto # 通用DTO定义
| |─contants
| | |─error-code.contants.ts # 系统错误码定义
| | |─decorator.contants.ts # 装饰器常量
| |─filters # 通用过滤器定义
| |─interceptors # 通用拦截器定义
| |─decorators # 通用装饰器定义
| |─exceptions # 系统内置通用异常定义
| |─class # Class Model 不使用Interface定义，使用Interface无法让Swagger识别
|─modules
| |─admin
| | |─core # 核心功能
| | | |─interceptors # 后台管理拦截器定义
| | | |─decorators # 后台管理注解定义
| | | |─provider # 后台管理提供者定义
| | | |─guards # 后台管理守卫定义
| | |─system # 系统模块定义
| | |─account # 用户账户模块定义
| | |─login # 登录模块定义
| | |─admin.module.ts # 后台管理模块
| | |─admin.constants.ts # 后台管理模块通用常量
| | |─admin.interface.ts # Admin通用interface定义
| |─ws # Socket模块
|─entities # TypeORM 实体文件定义
```

### 启动项目

依赖安装与执行打包命令前端与后端一致，但需要提前修改.env.development 中数据库相关配置，并执行 sql/init.sql 来初始化数据。

### 实现

项目中大部分的目录结构设计参照与[sf-nest-admin](https://github.com/hackycy/sf-nest-admin)，但主要为了贴合自我的代码风格修改部分数据字段名，接口方法，接口响应格式等等。

同时对于大部分这类后台管理的 demo，通常都会定义用户，角色，菜单，部门。而我将部门相关代码删除，因为对于我后续项目大概率用不上这些部分，然后删了一些不相关的模块，主要写的这套模板还是用作自己后续的管理类项目。

#### 用户-角色-权限

这套系统中最为重要的一部分便是权限管理，不过在这套后台管理系统中这里的权限与菜单共用，前端路由渲染菜单，后端鉴权。后文的菜单表也就作为权限表而言。

在这三张表中关系如下（这里使用外键与数据库模型为例，实际项目并未用到外键，也不推荐使用）

![image-20220508235534026](https://img.kuizuo.cn/image-20220508235534026.png)

用户-角色 与 角色-权限都采用的多对多的关系，即新创建一个表用于映射两表关系。这些都属于 mysql 基础，不做过多赘述。

在权限管理中，最为重要的便是权限表了，由于这套后台管理系统中还涉及到前端的左侧菜单，所以将这里的 permission 表替换为 menu 表，字段 permission 表示权限值。数据库中的 menu 表如下

![image-20220508234343594](https://img.kuizuo.cn/image-20220508234343594.png)

对于主要字段介绍：

- **parent**：对于有父子关系的表，会创建一个 parent_id(这里为 parent)字段用于表示父节点，无则为顶级节点。

- **permission**：权限标识，根据后端接口而定，比如新增用户的 url 为`sys/user/add`，那么权限标识通常将/替换成:，也就是`sys:user:add`（主要防止和接口的 url 混淆）。
- **type**：0 目录 1 菜单(前端组件) 2 权限，由于是菜单与权限混用，所以用 type 来区分。
- **icon**：左侧菜单图标
- **order_no**：左侧菜单排序
- **component**：组件，目录为 LAYOUT，菜单则为对应组件，权限则无

有了这些数据，要做的是将他们拼接为**前端菜单管理**，**根据角色获取所有菜单**，**根据用户的所有权限**的树结构数据。

##### 前端菜单管理

获取所有的菜单列表数据，通过递归生成对应的菜单树结构，具体递归代码在`src/modules/core/permission/index.ts`中的`generatorMenu`方法中。

具体拼接数据过多，可自行打开控制台(F12)->网络 到菜单管理页中获取数据可得，这里便不做展示（后文拼接数据同理）。

##### 根据角色获取所有菜单

首先根据用户 id 找到该用户的所有角色 id，然后通过联表找到角色 id 所对应的菜单数据。

```typescript
  /**
   * 根据角色获取所有菜单
   */
  async getMenus(uid: number): Promise<string[]> {
    const roleIds = await this.roleService.getRoleIdByUser(uid);
    let menus: SysMenu[] = [];
    if (includes(roleIds, this.rootRoleId)) {
      menus = await this.menuRepository.find({ order: { orderNo: 'ASC' } });
    } else {
      menus = await this.menuRepository
        .createQueryBuilder('menu')
        .innerJoinAndSelect('sys_role_menu', 'role_menu', 'menu.id = role_menu.menu_id')
        .andWhere('role_menu.role_id IN (:...roldIds)', { roldIds: roleIds })
        .orderBy('menu.order_no', 'ASC')
        .getMany();
    }

    const menuList = generatorRouters(menus);
    return menuList;
  }
```

同样`generatorRouters`函数也在`src/modules/core/permission/index.ts`中。

##### 根据用户的所有权限

与上例一样，不过这里主要获取的是 permission 字段，所以在条件上添加了`menu.type = 2`与`menu.permission IS NOT NULL`，将 permission 拼接为一个数组。

```typescript
  /**
   * 获取当前用户的所有权限
   */
  async getPerms(uid: number): Promise<string[]> {
    const roleIds = await this.roleService.getRoleIdByUser(uid);
    let permission: any[] = [];
    let result: any = null;
    if (includes(roleIds, this.rootRoleId)) {
      result = await this.menuRepository.find({
        permission: Not(IsNull()),
        type: 2,
      });
    } else {
      result = await this.menuRepository
        .createQueryBuilder('menu')
        .innerJoinAndSelect('sys_role_menu', 'role_menu', 'menu.id = role_menu.menu_id')
        .andWhere('role_menu.role_id IN (:...roldIds)', { roldIds: roleIds })
        .andWhere('menu.type = 2')
        .andWhere('menu.permission IS NOT NULL')
        .getMany();
    }
    if (!isEmpty(result)) {
      result.forEach((e) => {
        permission = concat(permission, e.permission.split(','));
      });
      permission = uniq(permission);
    }
    return permission;
  }
```

permission 的值如

```json
["sys:user:add", "sys:user:delete", "sys:user:update", "sys:user:list", "sys:user:info"]
```

然后在 auth.guard.ts 守卫中获取 permission，然后每次请求需要鉴权的接口时，将权限标识转为接口 url，判断是否包含该 url，不包含则无访问权限。

在[菜单管理页](https://admin.kuizuo.cn/#/system/menu)中可操作菜单，具体可自测。

至此，菜单表的数据被拆分为这 3 部分数据，以实现权限管理，动态路由的目的。

#### 其他文档

你可以访问 [https://admin.kuizuo.cn/swagger-ui](https://admin.kuizuo.cn/swagger-ui "https://admin.kuizuo.cn/swagger-ui") 来查看kz-admin的Swagger文档

json格式为 [https://admin.kuizuo.cn/swagger-ui/json](https://admin.kuizuo.cn/swagger-ui/json "https://admin.kuizuo.cn/swagger-ui/json")，用于导入ApiFox中。

ApiFox在线链接: [https://www.apifox.cn/apidoc/shared-7a07def2-5b82-4c71-bf57-915514f61f25](https://www.apifox.cn/apidoc/shared-7a07def2-5b82-4c71-bf57-915514f61f25 "https://www.apifox.cn/apidoc/shared-7a07def2-5b82-4c71-bf57-915514f61f25") 访问密码: kz-admin

## 写后感

其实一年多前我就想写一套相对完善的后台管理系统的模板，供自己后续的一些项目中使用。然而迟迟没有动手写套模板，而是不断根据业务需求，修修改改写了一套乱七八糟的代码，以至于维护的时候究极痛苦。就在不久前正好也用到，然而也是把之前写的屎山一样的代码拿来修改。

**我所遇到的问题：项目结构乱，代码风格乱，维护代码极其折磨**

所以今年寒假于是准备完善这套模板，然而当时只是创建完工程结构，到现在才正式把功能实现以及测试相关，部署搞定。说真的，非常拖延，甚至都快让我放弃写这个模板的打算。但拖也对我有一定的好处，为什么这么说？因为当时有这个想法时，市面上关于这套技术栈的实现还很少，而等我寒假再去搜索相关实现的时候，却有相关开源的代码，而这便可供我学习，使项目更加完善。

回顾整体项目的编写过程，所花费的时间可能一个月不到，甚至更少，但往往就是各种各样的拖延导致项目逾期，或者是学习某个技术栈。难以将精力集中起来完成任务，至于原因，也许是目标过于庞大，或许是日常生活中的各种琐事，不过我想多半是自我的懒惰。
