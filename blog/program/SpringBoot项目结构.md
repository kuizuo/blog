---
slug: springboot-project-structure
title: SpringBoot项目结构
date: 2022-01-08
authors: kuizuo
tags: [java, springboot, develop]
keywords: [java, springboot, develop]
---

<!-- truncate -->

演示代码地址：[kuizuo/spring-boot-demo (github.com)](https://github.com/kuizuo/spring-boot-demo)

## 目录结构展示图

![](https://img.kuizuo.cn/20220108011921.png)

### controller

controller 目录下对应的也就是控制器，用于接收用户的请求（get，post 等），如下面代码

```java title="controller/UserController.java"
@RestController
@RequestMapping("/user")
public class UserController {

    @Resource
    private UserService userService;

    @GetMapping("list")
    public List<User> list() {
        return userService.findAll();
    }
}
```

用户请求[http://127.0.0.1:8080/user/list](http://127.0.0.1:8080/users/list) 将会调用 userService.findAll 方法，当然这个方法事先定义好，用于获取所有用户。

### model（service）

这里数据库连接方式以 JPA（一个 ORM 框架）为例，可以安装一个 IDEA 插件 JPA Buddy 新建文件时可以直接创建 Entity(实体)或 Repository(仓库)

![image-20220506115207717](https://img.kuizuo.cn/image-20220506115207717.png)

#### entity 类

在 domain 目录下创建实体类，大致如下（lombok 因人而异选择使用，相对不展示 get 与 set 会好一些）

```java title="domain/User.java"
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Getter
@Setter
@Table(name = "user")
public class User implements Serializable {
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

User.java 用于定义 user 实体，在 ORM 中，数据库表中的字段都可以通过实体类中的属性来定义的，如果定义好 user 实体，并且在 resources/application.yml 中设置了`spring.jpa.hibernate.ddl-auto: update` 那么启动项目后，数据库将会自动创建 user 表且其表中字段自动为`@Column`注解的字段。

#### repository 类

创建完实体后，还需要定义数据接口访问层 DAO，在 JPA 中则是在 repository 目录下创建。

```java title="repository/UserRepository.java"
public interface UserRepository extends JpaRepository<User, Long> , JpaSpecificationExecutor<User> {
    User findByUsername(String username);
}
```

一般情况下该接口无需定义额外方法，如有需要还可以定义属于自己的查询语句，比如上面的 findByUsername，这时候就注入后的 userRepository 对象就可以使用`userRepository.findByUsername("kuizuo");` ，将会返回数据库中该用户名的数据。

#### UserService 类

```java title="service/UserService.java"
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public List<User> findAll(){
        return userRepository.findAll();
    }
}
```

**@Autowired 可能不建议使用字段注入**，可以在类添加@RequiredArgsConstructor 注解，表明 userRepository 不为空，总之目的就是将 userRepository 注入，供服务可用。

```java title="service/UserService.java"
import com.kuizuo.demo.domain.User;
import com.kuizuo.demo.repository.UserRepository;
import com.kuizuo.demo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    @Override
    public List<User> findAll() {
        return userRepository.findAll();
    }
}
```

接着就可以使用 userRepository 下的方法，如 `userRepository.findAll`命令相当于 `select * from user`，返回所有的用户列表。

#### service 接口实现

此外 service 服务还可以有另一种写法，在 service 中添加一个 impl 目录，通过对 userService **接口**进行实现的服务。
在上面所写的 UserService 是一个类，这边将其改为一个接口，代码如下

```java title="service/UserService.java"
public interface UserService {
    List<User> findAll();
    User findOne(Long id);
}
```

同时只保留 UserService 所要提供的方法，然后在 service/impl 中创建文件 UserServiceImpl.java，具体代码如下

```java title="service/impl/UserServiceImpl.java"
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;

    @Override
    public List<User> findAll() {
        return userRepository.findAll();
    }


    @Override
    public User findOne(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new BadRequestException("用户不存在"));
    }
}
```

调用并无差异，对 service 进一步的封装，相对更规范些（我看外面都这么写的，所以就这么写了）。

#### 数据接口

[POJO、PO、DTO、DAO、BO、VO 需要搞清楚的概念](https://developer.aliyun.com/article/694418)
此外还可能对不同层的数据进行命令

- 数据实体(entity)类`PO` ：
  - jpa 项目: domain 目录
  - mybatis 项目: entity 目录
- 数据接口访问层`DAO`：
  - jpa 项目： repository 目录
  - mybatis 项目： mapper 目录
- 数据传输对象`DTO`：dto 目录
- 视图对象`VO`：vo 目录

其中前两种在上文中 jpa 的例子中已经介绍了，简单介绍下后两者

`DTO` 经过处理后的 PO，在传输数据对象中可能增加或者减少 PO 的属性

`VO` 在控制层与视图层进行传输交换

对于后两者而言，可能还需要提供 Mapper 类用于数据转化，如 DTO 转 PO，PO 转 DTO。

##### modelMapper

```xml
<dependency>
    <groupId>org.modelmapper</groupId>
    <artifactId>modelmapper</artifactId>
    <version>2.3.5</version>
</dependency>
```

同时在启动类下配置为一个 Bean 才能被注入使用

```java
@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }
}

```

##### po 与 dto 转化

还是上面那个 user 实体，但是返回的数据中不需要将 user 的 password 展示出来。在 service/dto 中创建一个 UserDTO

```java title="service/dto/UserDto.java"
@Getter
@Setter
public class UserDto {
    private Long id;
    private String username;
    private String email;
}
```

如果要转化，通常要一个个字段转化，如下

```java {5-8}
    @Override
    public UserDto findOne(Long id) {
        User user =  userRepository.findById(id).orElseThrow(() -> new BadRequestException("用户不存在"));

        UserDto userDto = new UserDto();
        userDto.setId(user.getId());
        userDto.setUsername(user.getUsername());
        userDto.setEmail(user.getEmail());
        return userDto;
    }
```

结果肯定是没问题的，但是代码写的很丑陋且不易于维护。就可以使用 modelMapper 来转化（前提已经注入）

```java {5}
    private final ModelMapper modelMapper;

	@Override
    public UserDto findOne(Long id) {
        User user =  userRepository.findById(id).orElseThrow(() -> new BadRequestException("用户不存在"));

        UserDto userDto = modelMapper.map(user, UserDto.class);
        return userDto;
    }
```

不过这样使用可能还是不大规范，同时还需要手动传入对象及其 Class 对象。所以可能还会创建 service/mapstruct，然后创建 UserMapper，这里就不举例了。

### view

此外还有个文件 resources/templates/user.html 用于返回页面，不过这些都属于模板语言的内容，就不细说了（针对前后端分离的项目而言，后端主要提供数据便可）

### 整体流程

大致的流程便可总结为 Controller 接收请求 → 调用 service 服务 → 调用数据接口服务 dao 提供数据 → 将数据(页面)返回给用户

**此外，该目录结构仅仅本人所选用的 springboot 项目结构，实际情况还需额外考虑。**

## 总结

回到开头，其中提供业务服务（数据）的也就是 service 所做的事情，控制接口的则是 controller，还有一个视图层 view 介绍的比较少（反正就是返回数据或页面）。其中最为复杂的也就是 service 所提供的服务，相对 controller 和 view 而言会繁琐许多。
