---
id: frida-note
slug: /frida-note
title: Frida笔记
date: 2021-02-10
authors: kuizuo
tags: [frida, app, hook]
keywords: [frida, app, hook]
---

## 虚拟环境安装

由于 Python 版本兼容性问题，建议是安装虚拟环境

#### 安装 virtualenvwrapper

```sh
pip install virtualenvwrapper-win -i https://pypi.tuna.tsinghua.edu.cn/simple
```

#### 添加虚拟环境变量

添加一个 `WORKON_HOME` 为 `E:\Envs` （虚拟环境的路径）

#### 创建虚拟环境

`mkvirtualenv --python=python版本路径 环境名`

```sh
mkvirtualenv --python=E:\Python37\python.exe py37
mkvirtualenv --python=E:\Python38\python.exe frida
```

默认是用户路径下 `C:\Users\{username}\Envs\`

#### 进入虚拟环境

```sh
workon  #列出所有虚拟环境

workon 环境名  #进入对应名字下的虚拟环境
```

#### 退出虚拟环境

```sh
deactivate
```

### 删除虚拟环境（必须先退出虚拟环境内部才能删除当前虚拟环境）

```sh
rmvirtualenv 虚拟环境名称
```

### pip 相关指令

#### 查看虚拟环境中安装的包：

```sh
pip freeze

pip list
```

#### 收集当前环境中安装的包及其版本：

```sh
pip freeze > requirements.txt
```

#### 在部署项目的服务器中安装项目使用的模块：

```sh
pip install -r requirements.txt
```

## Frida

github 下载地址: [frida/frida](https://github.com/frida/frida)

文档: [Welcome | Frida • A world-class dynamic instrumentation framework](https://frida.re/docs/home/)

### 安装

```sh
pip install frida-tools  # 会自动帮你下载Frida 最新版
```

#### 安装指定版本

```sh
pip install frida==版本号
```

#### 查看 frida-tools 版本

因为 一个 frida-tools 会对应多个 frida 版，所以安装指定版本不能直接安装最新版，需查看对应版本号

访问 https://github.com/frida/frida/releases/tag/ + frida 版本号，找到 python3-frida-tools-版本号，即 frida-tools 版本号

```sh
pip install frida-tools==【frida-tools版本号】 # 无【】
```

#### 查看版本号，验证是否安装成功

```sh
frida --v
```

上述安装，有可能无法下载，建议科学上网，或使用 whl 离线安装

```
pip install frida-15.1.14-cp38-cp38-win_amd64.whl
pip install frida_tools-10.4.1-py3-none-any.whl
```

#### frida 代码提示

```
npm i @types/frida-gum
```

### frida 版本与 Android 版本与 Python 版本

| frida  | Android | Python |
| ------ | ------- | ------ |
| 12.3.6 | 5-6     | 3.7    |
| 12.8.0 | 7-8     | 3.8    |
| 14+    | 9+      | 3.8    |

### fridaserver

#### 安装

fridaserver 与 frida 版本需要匹配，和 frida-tools 一样，访问 https://github.com/frida/frida/releases/tag/ + frida 版本号，可以找到对应的 fridaserver 版本。

文件名的格式为：`frida-server-(version)-(platform)-(cpu).xz`，需要下载的安卓的也就是`frida-server-15.1.14-android-arm64.xz`， **解压后**将文件 push 到手机内`/data/local/tmp/`下，并重命名 fsarm64

```sh
adb push C:\Users\kuizuo\Desktop\frida-server-15.1.14-android-arm64 /data/local/tmp/fsarm64

adb shell
su
cd data/local/tmp
chmod 777 fsarm64

./fsarm64
```

#### 使用

```sh
# CMD 手机端
adb shell
su
./data/local/tmp/fsarm64 # 启动fs服务
# 可添加参数 -l 0.0.0.0:9000 指定端口为9000(默认27042),用于frida -H连接多个设备

# CMD 电脑端
workon frida #进入frida环境
frida -H -U -l hook.js
```

**新版本 fridaserver 无需端口转发**，旧版可能还需要新开一个 CMD 窗口执行`adb forward tcp:27042 tcp:27042`

## Frida 命令

Hook 前提: 在 hook 时，要保证参数类型执行流程与原代码保持一致，必要的调用与结果返回不可省略，否则将有可能导致程序崩溃。

`frida -help` 查看帮助，常用选项如下

| 选项                            | 功能                                               |
| ------------------------------- | -------------------------------------------------- |
| -U,–usb                         | 连接 USB 设备                                      |
| -F, --attach-frontmost          | app 最前显示的应用                                 |
| -H HOST, --host=HOST            | 通过端口连接 frida-server 默认监听 局域网 ip:27042 |
| -f FILE, --file=FILE spawn FILE | 以包名方式，自动启动 app 用%resume 恢复主线程      |
| -l SCRIPT, --load=SCRIPT        | 以 js 脚本方式注入                                 |
| -n NAME, --attach-name=NAME     | 以包名附加                                         |
| -p PID, --attach-pid=PID        | 以 PID 附加                                        |
| -o LOGFILE, --output=LOGFILE    | 将结果输出到文件上                                 |
| --debug                         | 附加到 Node.js 进行调试                            |
| --no-pause                      | 启动后，自动运行主线程 可省略%resume               |

### 简单 Hook 脚本演示

**注：Frida 老版本不支持 es6 语法。**

代码如下

```js title="hook.js"
// java层的代码 都需要在perform下执行
Java.perform(function () {
  // Java.use()   // 选择对应的类名 返回实例化的对象  可直接调用类下方法(反编译后查看)
  var Util = Java.use('com.dodonew.online.util.Utils')
  // 调用类下的md5方法 同时实现方法改为新函数
  Util.md5.implementation = function (a) {
    console.log('a: ', a)
    var ret = this.md5(a)
    console.log('ret: ', ret)
    return ret
  }
})
```

运行 `frida -U -F -l hook.js`，触发 hook 的函数，便可打印出参。

### 获取类

```javascript
// Java.use(类名)

let J_String = Java.use('java.lang.String')
let HashMap = Java.use('java.util.HashMap')
let Utils = Java.use('com.kuizuo.app.Utils')
```

### 静态方法与实例方法

```js
类.方法.implementation = function () {
  this.方法()
}

// 如果有返回值则需要将返回值返回

Util.md5.implementation = function (a) {
  console.log('a: ', a)
  let ret = this.md5(a)
  console.log('ret: ', ret)
  return ret
}

const HashMap = Java.use('java.util.HashMap')
HashMap.put.implementation = function (key, value) {
  console.log(JSON.stringify({ key: key.toString(), value: value.toString() }))
  let ret = this.put(key, value) // 如果不修改的话，则需要原封不动的传入。
  return ret
}
```

### 重载方法

如果方法有重载，需要使用`.overload('java.lang.String')` 给定参数个数与类型，如果有重载，但是不使用 overload，frida 将会报错

```javascript
Util.test.overload('java.lang.String').implementation = function (a) {
  let ret = this.test(a)
  return ret
}

Util.test.overload('int').implementation = function (a) {
  let ret = this.test(a)
  return ret
}
```

#### hook 所有重载方法

像上述两个重载方法，就需要编写两份代码，如果重载方法过多，代码不能很好的复用，就可以使用获取类下的所有重载方法

```javascript
类.方法.overloads // 返回所有重载方法,依次为每个成员实现implementation方法即可hook多个重载方法

let overloads = RequestUtil.encodeDesMap.overloads
for (const overload of overloads) {
  overload.implementation = function () {
    // console.log(Array.from(arguments));
    console.log([...arguments])
    // 两者都是打印参数，将类数组转真实数组

    return this.encodeDesMap(...arguments)
  }
}
```

### 构造方法

```javascript
类.$init.implementation = function () {
  this.$init()
}
```

### 实例化对象

```javascript
类.$new() // 等同于 new 类()
```

### 主动调用类方法

**以下的“类”，是通过`Java.use()`返回的值。**

#### 静态方法

```javascript
类.方法()
```

#### 实例方法 实例化对象

```javascript
let obj = 类.$new()
obj.方法()
```

#### 实例方法 获取已有对象(Java.choose)

内存中遍历，找到**所有**符合条件的对象。

```javascript
Java.choose('类路径', {
  onMatch: function (obj) {
    obj.方法()
  },
  onComplete: function () {
    console.log('内存中的对象搜索完毕')
  },
})
```

这样调用不优雅，会陷入回调地狱，所以可以封装成一个外部函数，来调用。（留个伏笔 TODO…）

### 修改函数参数与返回值

```javascript
Utils.md5.implementation = function (a) {
  let b = '随便设置的参数值'
  let result = this.md5(b) // 直接修改成b
  return '随便设置的返回值' // frida会将字符串包装成java的String对象。
  // return J_String.$new("随便设置的返回值");
}
```

### 获取与修改类字段(成员变量)

#### 静态字段

```javascript
类.字段.value // 获取类的属性值
类.字段.value = '新的值' // 修改类的值
```

#### 实例字段 实例化对象

```javascript
let obj = 类.$new()
obj.字段.value
```

#### 实例字段 获取已有对象(Java.choose)

```javascript
Java.choose('类路径', {
  onMatch: function (obj) {
    console.log(obj.字段.value)
  },
  onComplete: function () {},
})
```

:::tip

**注: 如果字段名与方法名一样，则需要给字段名前加下划线\_，否则获取到的是方法**

:::

### 内部类与匿名类

内部类

```javascript
const 外部类$内部类 = Java.use('外部类$内部类') // 变量命名随意
const 外部类$1 = Java.use('外部类$1') // 获取第一个内部类
```

匿名类

匿名类是根据内存生成，没有具体的内部类名，通过 smali 代码来判断，获取到的可能像下面这样

```javascript
const $1 = Java.use('包名.MainActivity$1')
```

### 枚举类

```javascript
Java.choose("枚举类" {
    onMatch: function (obj) {
        console.log(obj.ordinal()); // 输出枚举的键
    }, onComplete: function () {

    }
})
console.log(Java.use("枚举类").values()); // 输出值
```

### 获取所有类

```javascript
Java.enumerateLoadedClassesSync() // 同步获取已加载所有类,返回一个数组
Java.enumerateLoadedClasses() // 异步
```

#### 加载类下所有方法，属性

使用到 Java 的反射

```javascript
const Utils = Java.use('com.kuizuo.app.Utils')
const methods = Utils.class.getDeclaredMethods() // 方法
const constructors = Utils.class.getDeclaredConstructors() // 构造函数
const fields = Utils.class.getDeclaredFields() // 字段
const classes = Utils.class.getDeclaredClasses() // 内部类
const superClass = Utils.class.getSuperclass() // 父类(抽象类)
const interfaces = Utils.class.getInterfaces() // 所有接口

// 遍历输出
for (const method of methods) {
  console.log(method.getName())
}
// ...

for (const class$ of classes) {
  // class$ 为类的字节码，无需.class
  let fields = class$.getDeclaredFields()
  for (const field of fields) {
    console.log(field.getName())
  }
}
```

### 函数堆栈的打印

```javascript
function showStack() {
  Java.perform(function () {
    console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()))
  })
}
```

### HashMap 的打印

```javascript
RequestUtil.paraMap.overload('java.util.Map').implementation = function (a) {
  // // a是一个HashMap对象
  let key = a.keySet()
  let it = key.iterator()
  let obj = {}
  while (it.hasNext()) {
    let keystr = it.next()
    let valuestr = a.get(keystr)
    // keystr 与 valuestr 都是Java的对象，需要使用toString转成文本
    // 直接打印结果为 <instance: java.lang.Object, $className: java.lang.String>
    obj[keystr.toString()] = valuestr.toString()
  }
  console.log('obj: ', JSON.stringify(obj)) // 将打印成js的对象
  var result = this.paraMap(a)
  return result
}
```

### 安卓关键代码类

| 类名                    | 方法              | 作用                   |
| ----------------------- | ----------------- | ---------------------- |
| android.widget.Toast    | show              | 弹窗提示               |
| android.widget.EditText | getText           | 获取编辑框文本         |
| java.lang.StringBuilder | toString          | 字符串获取与拼接       |
| java.lang.String        | toString/getBytes | 获取字符串与字符串字节 |

### 写文件

写文件如果写入的不是私有空间的话，需要获取内部存储空间权限

私有空间 `/data/data/包名`、`/storage/emulated/0/Android/data/包名`

```javascript
let current_application = Java.use('android.app.ActivityThread').currentApplication()
let context = current_application.getApplicationContext()
let path = Java.use('android.content.ContextWrapper').$new(context).getExternalFilesDir('Download').toString()
console.log(path) // 获取app的私有空间 /storage/emulated/0/Android/data/包名/files/Download
let file = new File(path + '/test.txt', 'w')
file.write('内容')
file.flush()
file.close()
```

### 修改类型

Java.cast

```javascript
utils.shufferMap2.implementation = function (map) {
  console.log('map: ', map) // 传入的是HashMap对象，但是会向上转型为Map对象 输出[object Object]
  var hashMap = Java.cast(map, Java.use('java.util.HashMap'))
  console.log('hashMap: ', hashMap)
  return this.shufferMap2(hashMap)
}
```

### 构建 Java 数组

```javascript
// 普通字符串数组
let arr = Java.array('Ljava.lang.String;', ['字符串1', '字符串2', '字符串3'])

// 对象数组
let integer = Java.use('java.lang.Integer')
let boolean = Java.use('java.lang.Boolean')
let objarr = Java.array('Ljava.lang.Object;', ['字符串1', integer.$new(10), boolean.$new(true)])

// arrayList
var arrayList = Java.use('java.util.ArrayList').$new()
var integer = Java.use('java.lang.Integer')
var boolean = Java.use('java.lang.Boolean')
var Person = Java.use('com.kuizuo.app.Person')
var person = Person.$new('kuizuo', 20)
arrayList.add('kuizuo')
arrayList.add(integer.$new(10))
arrayList.add(boolean.$new(true))
arrayList.add(person)
```

注: 第一个参数类型给的是`Ljava.lang.String;` 而不是 `[Ljava.lang.String;`

#### 指定函数下 hook(取消 hook)

`HashMap.put.implementation = null` 取消对 HashMap.put 方法的 hook

```javascript
const HashMap = Java.use('java.util.HashMap')
RequestUtil.paraMap.overload('java.util.Map').implementation = function (a) {
  // a是一个HashMap对象
  HashMap.put.implementation = function (key, value) {
    // 只在RequestUtil.paraMap方法调用的时候才会打印HashMap传入的参数
    console.log(JSON.stringify({ key: key.toString(), value: value.toString() }))
    let ret = this.put(key, value)
    return ret
  }
  var result = this.paraMap(a)
  HashMap.put.implementation = null
  return result
}
```

### dex 加载

#### 注入一个类 registerClass

[JavaScript API | Frida • A world-class dynamic instrumentation framework](https://frida.re/docs/javascript-api/#java-cast)

通常是加载某个类，复写某些方法，达到绕过的目的，如证书效验

但此方法相对繁琐，不如直接编写 java 代码编译成 dex 直接注入来的方便，也就有了 dex 的动态加载。

#### DexClassLoader

```javascript
Java.perform(function () {
  // console.log(Java.enumerateLoadedClassesSync().join("\n"));
  // var dynamic = Java.use("com.xiaojianbang.app.Dynamic");
  // console.log(dynamic);

  // Java.enumerateClassLoaders({
  //     onMatch: function (loader){
  //         try {
  //             Java.classFactory.loader = loader;
  //             var dynamic = Java.use("com.xiaojianbang.app.Dynamic");
  //             console.log("dynamic: ", dynamic);
  //             //console.log(dynamic.$new().sayHello());
  //             dynamic.sayHello.implementation = function () {
  //                 console.log("hook dynamic.sayHello is run!");
  //                 return "xiaojianbang";
  //             }
  //         }catch (e) {
  //             console.log(loader);
  //         }
  //     }, onComplete: function () {
  //
  //     }
  // });

  var dexClassLoader = Java.use('dalvik.system.DexClassLoader')
  dexClassLoader.loadClass.overload('java.lang.String').implementation = function (className) {
    //console.log(className);
    var result = this.loadClass(className)
    //console.log("class: ", result);
    //console.log("class.class: ", result.class);
    //console.log("xxxxxxxx: ", result.getDeclaredMethods());
    if ('com.xiaojianbang.app.Dynamic' === className) {
      Java.classFactory.loader = this
      var dynamic = Java.use('com.xiaojianbang.app.Dynamic')
      console.log('dynamic: ', dynamic)
      //var clazz = dynamic.class;
      //console.log("xxxxxxxx: ", clazz.getDeclaredMethods()[0].invoke(clazz.newInstance(), []));
      //console.log(dynamic.$new().sayHello());
      dynamic.sayHello.implementation = function () {
        console.log('dynamic.sayHello is called')
        return 'xiaojianbang'
      }
      console.log(dynamic.$new().sayHello())
    }
    return result
  }
})
```

### dx

bat: android\SDK\build-tools\sdk 版本\dx.bat

jar 包: android\SDK\build-tools\sdk 版本\lib\dx.jar

#### 使用

```sh
dx --dex --output=C:\Users\zeyu\Desktop\com\output.dex C:\Users\zeyu\Desktop\com\*
```

`C:\Users\zeyu\Desktop\com\*`下存放 java 代码编译后的.class 将其转为 dex 文件，也可指定.class 文件

注: `C:\Users\zeyu\Desktop\com\*` 绝对路径可能会报错，可使用相对路径。

#### baksmali 与 smali

github: [JesusFreke/smali: smali/baksmali (github.com)](https://github.com/JesusFreke/smali)

下载地址: [JesusFreke / smali / Downloads — Bitbucket](https://bitbucket.org/JesusFreke/smali/downloads/)

baksmali 将 dex 编译成 smali

smali 将 smali 编译成 dex

##### 使用

反编译 dex

```sh
java -jar baksmali-2.5.2.jar d classes.dex # 将会生成out的文件夹
```

回编译 dex

```sh
java -jar smali-2.5.2.jar a out # 将会生成out.dex文件
```

#### apktool

[iBotPeaches/Apktool: A tool for reverse engineering Android apk files (github.com)](https://github.com/iBotPeaches/Apktool)

安装文档: [Apktool - How to Install (ibotpeaches.github.io)](https://ibotpeaches.github.io/Apktool/install/)

#### apksigner

jar 包: android\SDK\build-tools\sdk 版本\lib\apksigner.jar

```
apksigner sign --ks xxx.jks xxx.apk
Keystore password for signer #1:
#
```

#### frida 注入 dex 文件

```
Java.openClassFile("/data/local/tmp/xxx.dex").load();

// 就可以在内存中使用加载后的类
```

## 脱离 PC 使用 frida

### Termux

使用 Termux 终端，补齐 python，node 环境，相当于手机端运行电脑端的 frida，本质上与电脑端相同。

### frida-inject

同 fridaserver，下载 frida-inject 移动到手机上，

```
adb push C:\Users\kuizuo\Desktop\frida-inject-15.1.14-android-arm64 /data/local/tmp/fiarm64

adb shell
su
cd data/local/tmp
chmod 777 fiarm64
```

##### 使用

前提，hook 的 js 脚本也移动到 fiarm64 相同路径或指定路径。

```sh
./fiarm64 -n 包名 -s 脚本.js
./fiarm64 -p pid -s 脚本.js # ps -A 可查看pid
```

可以加-e，–eternalize 使其在后台运行。

### frida-gadget.so

**免 root 使用 frida**，但需要重打包 app，比较稳定。可通过魔改系统，让系统帮我们注入 so，免去重打包的繁琐

##### 环境

abd、aapt、jarsigner、apksigner、apktool（这些都需要添加到环境变量中）

##### 使用

使用到 objection patchapk 命令，选项如下

| 选项                    | 例子          | 功能                                                     |
| ----------------------- | ------------- | -------------------------------------------------------- |
| -s xxx.apk              | -s xxx.apk    | 指定 apk 文件                                            |
| -a so 版本              | -a arm64-v8a  | 指定安卓 so 版本                                         |
| -V frida-gadget 版本号  | -V 15.1.14    | 指定 frida-gadget 版本号，默认最新                       |
| -d, –enable-debug       | -d            | 是否允许调试                                             |
| -c, –gadget-config TEXT | -c config.txt | 加载[配置](https://frida.re/docs/gadget/#script)方式打包 |

frida-gadget 可能会下载失败，去 github 下载[frida-gadget-15.1.14-android-arm64.so.xz](https://github.com/frida/frida/releases/download/15.1.14/frida-gadget-15.1.14-android-arm64.so.xz)，解压后将 gadget 文件更名`libfrida-gadget.so`为存放到`C:\Users\zeyu\.objection\android\arm64-v8a`

执行

```
objection patchapk -a arm64-v8a -V 15.1.14 -s xxx.apk
```

将会生成 xxx.objection.apk 文件，卸载原 app（与原 apk 签名不一样，无法覆盖安装），重新安装

重新打开将会进入白屏，正常现象，等待 frida 去连接，相当于 apk 中运行了一个 frida-server。
