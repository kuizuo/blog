---
title: SpringBoot热加载
date: 2022-01-10
authors: kuizuo
tags: [java, springboot]
---

<!-- truncate -->

## 步骤一

pom.xml中在加入依赖

```xml
<dependency>
 	<groupId>org.springframework.boot</groupId>
 	<artifactId>spring-boot-devtools</artifactId>
 	<optional>true</optional>
	<scope>true</scope>
</dependency>
```

然后再`<build>`下添加如下依赖。

```xml
<build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <fork>true</fork>
                </configuration>
            </plugin>
        </plugins>
    </build>
```

## 步骤二

（1）打开设置勾选自动构建项目

![image-20220506130419248](https://img.kuizuo.cn/image-20220506130419248.png)

（2）高级设置中勾选自动make，老版IDEA需要`ctrl + shift + alt + /`，选择注册表，勾上Compiler autoMake allow when app running，但新版中移到高级设置中。

![image-20220506130533312](https://img.kuizuo.cn/image-20220506130533312.png)

接着启动项目，修改文件即可自动热加载，无需手动重新运行。