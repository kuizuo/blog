---
title: SpringBoot项目目录结构
date: 2022-01-08
tags:
  - java 
  - springboot
  - 开发
---

<!-- truncate -->

## 目录结构展示图

![](https://img.kuizuo.cn/20220108011921.png)
### controller
controller目录下对应的也就是控制器，用于接收用户的请求（get，post等），如下面代码
```Java
@RestController
@RequestMapping("/users")
public class UserController {

    @Resource
    private UserService userService;

    @GetMapping("list")
    public List<User> list() {
        return userService.findAll();
    }
}
```

用户请求[http://127.0.0.1:8080/users/list](http://127.0.0.1:8080/users/list) 将会调用userService.findAll方法，当然这个方法事先定义好，用于获取所有用户。
### model（service）
UserService代码
```Java
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public List<User> findAll(){
        return userRepository.findAll();
    }
}
```

这边注入了`userRepository `，也就是操作user表的数据库，由于这里使用的是ORM 框架 jpa，所以`userRepository.findAll`命令相当于 `select * from user`，当时前提我们得先定义UserRepository 与 User实现，这样我们才能使用该命令，两部分的代码分别如下
#### repository类
repository/UserRepository.java
```Java
public interface UserRepository extends JpaRepository<User, Long> , JpaSpecificationExecutor<User> {

}
```

#### entity类
domain/User.java
```Java
@Entity
@NoArgsConstructor
@Getter
@Setter
@Table(name = "user")
public class User implements Serializable {
    public User(String username, String password, String email) {
        this.username = username;
        this.password = password;
        this.email = email;
    }

    @Id
    @GeneratedValue
    @ApiModelProperty(value = "ID", hidden = true)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;
    @Column(nullable = false)
    private String password;
    @Column(nullable = false)
    private String email;
}
```

User.java用于定义user实体，在ORM中，数据库表中的字段都可以通过实体类中的属性来定义的，如果定义好user实体，并且jpa设置了`jpa.hibernate.ddl-auto: update` 那么启动项目后，数据库将会自动创建user表，字段则为username password email。
在UserRepository中我们还可以定义属于自己的查询语句，比如
`User findByUsername(String username);`
这时候使用`userRepository.findByUsername("kuizuo");` 便会返回数据库中该用户名的user java对象。
#### service接口实现
此外service服务还可以有另一种方式，在service中添加一个impl目录，通过对userService **接口**进行实现的服务。
在上面所写的UserService 是一个类，这边将其改为一个接口，代码如下
```Java
public interface UserService {
    List<User> findAll()；
}
```

同时只保留UserService 所要提供的方法，然后创建文件UserServiceImpl.java，覆写UserService 接口中的所有方法， 具体代码如下
```Java
@Service
public class UserServiceImpl implements UserService  {

    @Autowired
    private UserRepository userRepository;

    @Override
    public List<User> findAll(){
        return userRepository.findAll();
    }
}

```

调用并无差异，与原本的UserService 的区别就是加注解@Service与implements实现，对service 进行进一步的封装，调用只需要关注 service 接口层即可，相对更规范些。
#### 数据接口
[POJO、PO、DTO、DAO、BO、VO需要搞清楚的概念](https://developer.aliyun.com/article/694418)
此外还可能对不同层的数据进行命令
- 数据实体(entity)类`PO` ：
	- jpa项目: domain目录
	- mybatis项目: entity目录
- 数据接口访问层`DAO`：
	- jpa项目： repository目录
	- mybatis项目： mapper目录
- 数据传输对象`DTO`：dto目录
- 视图对象`VO`：vo目录

其中前两种在上文中jpa的例子中已经介绍了，简单介绍下后两者

`DTO` 经过处理后的PO，在传输数据对象中可能增加或者减少PO的属性

`VO` 在控制层与视图层进行传输交换

对于后两者而言，可能还需要提供Mapper类用于数据转化，如DTO转PO，PO转DTO。

根据实际业务而定，具体实现的代码就不做演示了。

### view

此外还有个文件resources/templates/user.html 用于返回页面，不过这些都属于模板语言的内容，就不细说了（针对前后端分离的项目而言，后端主要提供数据便可）

### 整体流程

大致的流程便可总结为 Controller接收请求→调用service服务→调用数据库服务提供数据→将数据(页面)返回给用户

如果新的需求是要加入角色相对应的模块，只需要在对应的文件夹中分别创建角色所对应的文件。

**此外，该目录结构仅仅本人所选用的springboot项目结构，实际情况还需额外考虑。**

## 总结

回到开头，其中提供业务服务（数据）的也就是service所做的事情，控制接口的则是controller，还有一个视图层 view 介绍的比较少（反正就是返回数据或页面）。其中最为复杂的也就是service所提供的服务，相对controller和view 而言会繁琐许多。不过思考下，如果service层中findAll返回的是一串固定的Java List对象，那么就没有数据库的事情，也就没有实体，与repository的用武之地了，更不会有userRepository注入了。



