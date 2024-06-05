---
slug: java-reflect
title: java反射
date: 2022-01-16
authors: kuizuo
tags: [java]
keywords: [java]
---

<!-- truncate -->

## 什么是反射？　　

Java 反射（Reflection）就是在运行状态中，对于任意一个类，都能够知道这个类的所有属性和方法；对于任意一个对象，都能够调用它的任意方法和属性；并且能改变它的属性。（摘自网络）

## 反射能做什么？

由于我们能够知道这个类的所有属性和方法，并且可以调用其方法与属性，那么我们就可以在外部，不通过修改类的形式来给类增加额外自定义功能。

在一些框架开发中，可以更灵活的编写代码，在运行时装配无需针对原类进行大幅度改动，降低代码耦合度。

在安卓逆向中，反射的主要作用就是寻找到某个类，去注入我们的代码，以便查看调用前后的参数与结果，也称之为 hook。

## 反射常用 API

### 获取 Class 对象

在反射中，要获取一个类或调用一个类的方法，我们首先需要获取到该类的 Class 对象，获取 Class 类对象以下方法：

**1、使用 Class.forName 静态方法。当你知道该类的全路径名时，你可以使用该方法获取 Class 类对象。**

```java
Class cls = Class.forName("java.lang.String");
```

**2、使用 .class 方法。**

这种方法只适合在编译前就知道操作的 Class。

```java
Class cls = String.class;
```

**3、使用类对象的 getClass() 方法。**

```java
String str = new String("Hello");
Class cls = str.getClass();
```

**4、ClassLoader.loadClass()**

前提：已经获取到 ClassLoader 的情况下（Person 是定义好的类，其中`String.class.getClassLoader()`获取到得为 null）

```java
ClassLoader clsl = Person.class.getClassLoader();
Class<?> cls = clsl.loadClass("Person");
```

基本数据类型的类对象获取 `int.class` `Integer.TYPE` 得到`int`

包装类的 Class 类对象获取 `Integer.class` 得到 `class java.lang.Integer`

#### 哪些有 Class 对象

并非所有 java 对象都有 Class 对象，获取方式如上

- 外部类
- 内部类

内部类的获取方式通过$连接外部类与内部类，多个内部类也可通过$1，$2 依次获取

```java
Class cls1 = Class.forName("OutClass$InnerClass");
Class cls2 = Class.forName("OutClass$1");
```

- 接口 =>`interface DemoI`
- 数组 => `class [Ljava.lang.String;`
- 枚举 enum
- Thread.State
- 注解 anntation
- 基本数据类型
- 包装类
- void

### 创建类对象（与获取构造函数）

**1、通过 Class 对象的 newInstance 方法**（无法传参）

```java
Person p = Person.class.newInstance();
// 相当于 Person p = new Person();
```

**2、通过 Constructor 对象的 newInstance() 方法** （可传参数）

可以传参数，但需要知道传入参数类型，以确定哪个构造函数。

```java
Constructor<Person> constructor = Person.class.getConstructor(String.class);
Person p = constructor.newInstance("kuizuo");
```

如果构造函数是私有方法，则通过`getDeclaredConstructor`获取 Constructor

同时设置是否访问 `constructor.setAccessible(true)` 才可访问

```java
Constructor<Person> constructor = Person.class.getDeclaredConstructor(String.class);
constructor.setAccessible(true);
Person p = constructor.newInstance("kuizuo");
```

**getParamerTypes** 获取参数类型数组(Class [])

**要获取私有属性，私有方法或私有构造器，则必须使用有 declared 关键字的方法。**

### 获取类属性

- **getField **只可获取公有属性

```java
Field nameField = Person.class.getField("name");
String name =(String) nameField.get(p);
```

设置属性值

```java
Field nameField = Person.class.getField("name");
nameField.set(p,"kuizuo12");
```

设置静态属性值 set 第一个参数给 null 即可

```java
Field nameField = Person.class.getField("name");
nameField.set(null,"kuizuo12");
```

- **getDeclaredField **只可获取所有属性
- **getFields** 获取所有共有属性
- **getDeclaredFields** 获取所有属性

```java
  Field[] fields = Person.class.getDeclaredFields();
  for (Field field : fields) {
      System.out.println(field.getName());
  }
```

### 获取类方法

- **getMethod** 获取

参数一为方法名，其余参数为参数类型

调用通过`method.invoke`调用，参数一为对象，其余参数为实参

```java
Method method = Person.class.getMethod("say", String.class);
method.invoke(p, "hello")；

```

**如果是静态方法，invoke 第一个参数可传入 null**

- **getDeclaredMethod** 可获取私有方法 （也需要 setAccessible）

```java
Method method = Person.class.getDeclaredMethod("say", String.class);
method.setAccessible(true);
method.invoke(p, "hello");
```

- **getMethods** 获取所有公有方法
- **getDeclaredMethods**获取所有方法

```java
Method[] methods = Person.class.getDeclaredMethods();
for (Method method : methods) {
    System.out.println(method.getName());
}
```

### 获取父类

- **getSuperclass**

接口无父类

### 获取内部类

- **getClasses**

```java
Class<?>[] classes = Person.class.getClasses();
System.out.println(classes[0]);
```

- **getDeclaredClasses** 获取所有内部类（包括私有）

### 获取接口

前提：实现（implements）一个接口

```java
Class<?>[] interfaces = Person.class.getInterfaces();
System.out.println(interfaces.length);
```

### 其他方法

官方文档 [Class (Java Platform SE 8 ) (oracle.com)](https://docs.oracle.com/javase/8/docs/api/)

大致常用的方法如上，其余的 Class 类的方法还有

- getName 获取全类名
- getSimpleName 获取简单类名
- getModifiers 获取标识符
- getAnnotations 获取注解
- getPackage 获取包名

具体代码就不演示了。
