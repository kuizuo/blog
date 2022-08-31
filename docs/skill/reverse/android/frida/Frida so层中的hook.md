---
id: frida-so-hook
slug: /frida-so-hook
title: Frida so层中的hook
date: 2021-02-10
authors: kuizuo
tags: [frida, app, hook]
keywords: [frida, app, hook]
---

<!-- truncate -->

## 前言

so 中会接触到的东西：系统库函数、加密算法、jni 调用、系统调用、自定义算法

## 如何 hook

so hook 只需要得到一个地址，有**函数地址就能 hook 与主动调用**，与 java 层的 hook 一致。

### 得到函数地址的方式

1. 通过 frida 提供的 api 来得到，该函数必须有符号的才可以
2. 通过计算得到地址：so 基址+函数在 so 中的偏移[+1]

### 演示代码如下

```javascript
const moduleName = 'libnative-lib.so'
let baseAddr = Module.findBaseAddress(moduleName)
let sub_99C0 = baseAddr.add(0x99c0 + 1)
Interceptor.attach(funcPtr, {
  onEnter: function (args) {
    // ...
  },
  onLeave: function (retval) {
    // ...
  },
})
```

## API

### 枚举导入表

```javascript
const improts = Module.enumerateImports('libencryptlib.so')
for (const iterator of improts) {
  console.log(JSON.stringify(iterator))
  // {"type":"function","name":"__cxa_atexit","module":"/apex/com.android.runtime/lib64/bionic/libc.so","address":"0x778957bd34"}
}
```

### 枚举导出表

```javascript
const exports = Module.enumerateExports('libencryptlib.so')
for (const iterator of exports) {
  console.log(JSON.stringify(iterator))
  // {"type":"letiable","name":"_ZTSx","address":"0x74d594b1c0"}
}
```

### 枚举符号表

```javascript
const symbols = Module.enumerateSymbols('libencryptlib.so')
for (const iterator of symbols) {
  console.log(JSON.stringify(iterator))
  // {"isGlobal":true,"type":"function","name":"pthread_getspecific","address":"0x0","size":0
}
```

### 枚举进程中已加载的模块

```javascript
const modules = Process.enumerateModules()
console.log(JSON.stringify(modules[0].enumerateExports()[0]))
```

### findExportByName

注: **函数名以汇编中出现的为准**

```javascript
const funcAddr = Module.findExportByName('libencryptlib.so', '_ZN7MD5_CTX11MakePassMD5EPhjS0_')
// 返回的是函数地址  第二个参数根据汇编中为准
console.log(funcAddr)

// 通过Interceptor.attach来对函数进行hook
Interceptor.attach(funcAddr, {
  onEnter: function (args) {
    console.log('args[1]: ', hexdump(args[1])) // 打印参数的地址 通过hexdump打印16进制
    console.log(this.context.x1) // 打印寄存器内容
    console.log('args[2]: ', args[2].toInt32()) // 默认显示16进制,这里转为10进制
    this.args3 = args[3] // 将args[3]值保存到this上
  },
  onLeave: function (retval) {
    console.log('args[3]: ', hexdump(this.args3))
  },
})
```

### 模块基址获取方式

如果在导入表、导出表、符号表里找不到的函数，那么函数地址需要自己计算

计算公式：**so 基址+函数在 so 中的偏移[+1]**

| 安卓位数 | 指令  | 计算方式                         |
| -------- | ----- | -------------------------------- |
| 32 位    | thumb | so 基址 + 函数在 so 中的偏移 + 1 |
| 64 位    | arm   | so 基址 + 函数在 so 中的偏移     |

也可通过显示汇编指令对应的 opcode bytes，来判断

IDA -> Options -> General -> Number of opcode bytes (non-graph) 改为 4

![image-20220206042920297](https://img.kuizuo.cn/20220206042927.png)

arm 指令为 4 个字节，如果函数中有些指令是两个字节，那么函数地址计算需要 + 1

**不清楚的话，+1 和不+1 都试一遍即可**

所以获取基址就显得尤为重要

#### Process.findModuleByName

通过模块名找到模块

```javascript
const module = Process.findModuleByName('libencryptlib.so')
console.log(JSON.stringify(module))
// {"name":"libencryptlib.so","base":"0x74d5934000","size":303104,"path":"/data/app/~~Nzn4SQ_RZn1-PYH7TbX7Ig==/com.pocket.snh48.activity-Muxx7c_dtplxjFPY2SGF0A==/lib/arm64/libencryptlib.so"}
// base为基址
```

#### Process.getModuleByName

同 findModuleByName

#### Module.findBaseAddress()（常用）

直接获得模块基址

```javascript
const baseAddr = Module.findBaseAddress('libencryptlib.so')
console.log(baseAddr)
// 0x74d5934000
```

#### Process.findModuleByAddress(address)

通过基址来找到模块

#### Process.getModuleByAddress(address)

同 findModuleByAddress

#### 测试 hook 任意函数

```javascript
const baseAddr = Module.findBaseAddress('libencryptlib.so')
// const so = 0x77ab999000;
// console.log(ptr(so).add(0x1FA38)); // ptr 是 new NativePointer()的简写
const funcAddr = baseAddr.add(0x1fa38) // 0x1FA38 是IDA中函数定义的地址
Interceptor.attach(funcAddr, {})
```

#### 打印参数

```javascript
function print_arg(addr) {
  const module = Process.findRangeByAddress(addr)
  // 判断传入的参数是否为地址
  if (module !== null) return hexdump(addr) + '\n'
  return ptr(addr) + '\n'
}
```

#### 参数的方法

```javascript
// args[0] 是一个内存地址
hexdump(args[0]) // 打印参数的所在内存区域的字节数据
args[0].readCString() // 读取参数所对应的C字符串 (前提: 参数是一个可见字符串)
args[0].readPointer() // 用读地址方式去读取参数所对应的值 (如果参数是一个指针的话可能就需要使用)
```

### 修改函数数值参数和返回值

#### 修改数值

```javascript
Interceptor.attach(helloAddr, {
  onEnter: function (args) {
    args[2] = ptr(1000) // 直接将第三个参数修改为1000
    console.log(args[2].toInt32())
  },
  onLeave: function (retval) {
    retval.replace(20000) // 通过replace 修改成20000
    console.log('retval', retval.toInt32())
  },
})
```

### 修改字符串

hex 与 string 转化封装函数（中文无法转化）

```javascript
function stringToBytes(str) {
  return hexToBytes(stringToHex(str))
}

function stringToHex(str) {
  return str
    .split('')
    .map(function (c) {
      return ('0' + c.charCodeAt(0).toString(16)).slice(-2)
    })
    .join('')
}

function hexToBytes(hex) {
  for (let bytes = [], c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16))
  return bytes
}

function hexToString(hexStr) {
  let hex = hexStr.toString()
  let str = ''
  for (let i = 0; i < hex.length; i += 2) str += String.fromCharCode(parseInt(hex.substr(i, 2), 16))
  return str
}
```

#### 将指向的字符串修改成新的字符串（新字符串不宜超过原有字符串长度）

```javascript
Interceptor.attach(funcAddr, {
  onEnter: function (args) {
    let newStr = 'some strings'
    // 需要写入字节数组的方式来写入字符串
    args[1].writeByteArray(hexToBytes(stringToHex(newStr) + '00')) // c语言字符串结尾为0字节
    console.log(hexdump(args[1]))
    args[2] = ptr(newStr.length)
    console.log(args[2].toInt32())
  },
  onLeave: function (retval) {},
})
```

:::danger

有缺陷，如果字符串长度大于原字符串长度，有可能导致内存中其他区域被修改，导致不可预知的 BUG

:::

#### 将 so 层中已有的字符串传给函数（字符串地址替换）

```javascript
Interceptor.attach(funcAddr, {
  onEnter: function (args) {
    args[1] = baseAddr.add(0x38a1) // 0x38a1 为IDA中所对应的字符串地址
    console.log(hexdump(args[1]))
    args[2] = ptr(baseAddr.add(0x38a1).readCString().length) // 读取字符串长度
    console.log(args[2].toInt32())
  },
  onLeave: function (retval) {},
})
```

#### 替换函数（建议使用）

```javascript
cosnt newStr = "some strings";
cosnt newStrAddr = Memory.allocUtf8String(newStr); // 使用Frida的Memory来申请内存区域 返回的是一个指针

Interceptor.attach(funcAddr, {
  onEnter: function (args) {
    // cosnt newStrAddr = Memory.allocUtf8String(newStr); // 如果在这里申请的话,到onLeave将会回收 可以在全局定义或使用this.newStrAddr 附加到自身
    args[1] = newStrAddr
    console.log(hexdump(args[1]))
    args[2] = ptr(newStr.length)
    console.log(args[2].toInt32())
  },
  onLeave: function (retval) {},
})


```

### 内存读写

```javascript
// 1. 读取指定地址的字符串
let baseAddr = Module.findBaseAddress('libxiaojianbang.so')
console.log(baseAddr.add(0x2c00).readCString())

// 2. dump指定地址的内存
console.log(hexdump(baseAddr.add(0x2c00)))

// 3. 读指定地址的内存
console.log(baseAddr.add(0x2c00).readByteArray(16))
console.log(Memory.readByteArray(baseAddr.add(0x2c00), 16)) //原先的API

// 4. 写指定地址的内存
baseAddr.add(0x2c00).writeByteArray(stringToBytes('xiaojianbang'))
console.log(hexdump(baseAddr.add(0x2c00)))

// 5. 申请新内存写入
Memory.alloc()
Memory.allocUtf8String()

// 6. 修改内存权限
Memory.protect(ptr(libso.base), libso.size, 'rwx')
```

### 修改 so 函数代码（需了解 ARM 汇编相关知识）

```javascript
// 1. 修改地址对应的指令
let baseAddr = Module.findBaseAddress("libxiaojianbang.so");
baseAddr.add(0x1684).writeByteArray(hexToBytes("0001094B"));
ARM与Hex在线转换 https://armconverter.com/

// 2. 将对应地址的指令解析成汇编
let ins = Instruction.parse(baseAddr.add(0x1684));
console.log(ins.toString());

// 3. 利用frida提供的api来写汇编代码
new Arm64Writer(baseAddr.add(0x167C)).putNop();
console.log(Instruction.parse(baseAddr.add(0x167C)).toString());

// 4. 利用frida提供的api来写汇编代码
let codeAddr = baseAddr.add(0x167C);
Memory.patchCode(codeAddr, 8, function (code) {
    let Writer = new Arm64Writer(code, {pc: codeAddr});
    Writer.putBytes(hexToBytes("0001094B"));
    Writer.putBytes(hexToBytes("FF830091"));
    Writer.putRet();
    Writer.flush();
});
```

### 主动调用任意函数

1. 声明函数指针

   文档：https://frida.re/docs/javascript-api/#NativeFunction
   语法：`new NativeFunction(address, returnType, argTypes[, abi])`

2. 支持的 returnType 和 argTypes

   void、pointer、int、uint、long、ulong、char、uchar、float、double
   int8、uint8、int16、uint16、int32、uint32、int64、uint64、bool
   size_t、ssize_t

3. 代码示例

   ```javascript
   Java.perform(function () {
     //拿到函数地址
     let funcAddr = Module.findBaseAddress('libxiaojianbang.so').add(0x23f4)
     //声明函数指针
     let func = new NativeFunction(funcAddr, 'pointer', ['pointer', 'pointer'])
     let env = Java.vm.tryGetEnv() // 获取JNIEnv
     console.log('env: ', JSON.stringify(env))
     // {"handle":"0xb400007911df2c10","vm":{"handle":"0xb400007921d5f710"}}
     if (env != null) {
       // 创建java字符串 (jstr是一个地址)
       let jstr = env.newStringUtf('some strings')
       let cstr = func(env, jstr)
       console.log(cstr.readCString())
       console.log(hexdump(cstr))
     }
   })
   ```

### hook libc.so 读写文件

```javascript
// 找到C中操作文件的api
let fopenAddr = Module.findExportByName('libc.so', 'fopen')
let fputsAddr = Module.findExportByName('libc.so', 'fputs')
let fcloseAddr = Module.findExportByName('libc.so', 'fclose')
console.log(fopenAddr, fputsAddr, fcloseAddr)

let fopen = new NativeFunction(fopenAddr, 'pointer', ['pointer', 'pointer'])
let fputs = new NativeFunction(fputsAddr, 'int', ['pointer', 'pointer'])
let fclose = new NativeFunction(fcloseAddr, 'int', ['pointer'])

// 需要申请内存地址 (由于需要传入指针)
let fileName = Memory.allocUtf8String('/data/data/com.xiaojianbang.app/xiaojianbang.txt')
let openMode = Memory.allocUtf8String('w')
let data = Memory.allocUtf8String('QQ24358757\n')

let file = fopen(fileName, openMode)
console.log(file)
fputs(data, file)
fclose(file)
```

### hook jni 函数

libart.so 存放 jni 函数

**jni 文档可在 jni.h 头文件中查看**

安卓 10 以下 `/system/lib` 或 `/system/lib64`

安卓 10 以后 `/system/apex/com.android.runtime.release/lib64/libart.so`

例如 hook env->NewStringUTF()方法

```javascript
// 找到 env->NewStringUTF(a1, str) 函数
function findNewStringUtfAddr() {
  let artSym = Module.enumerateSymbols('libart.so')
  for (const sym of artSym) {
    if (!sym.name.includes('CheckJNI') && sym.name.includes('NewStringUTF')) {
      // console.log(JSON.stringify(sym));
      return sym.address
    }
  }
  return null
}

function hookNewStringUTF() {
  const NewStringUTFAddr = findNewStringUtfAddr()
  // console.log('NewStringUTFAddr', NewStringUTFAddr);
  if (NewStringUTFAddr !== null) {
    Interceptor.attach(NewStringUTFAddr, {
      onEnter: function (args) {
        console.log(args[1].readCString())
      },
      onLeave: function (retval) {},
    })
  }
}
hookNewStringUTF()
```

计算地址方式（了解）

```javascript
Java.perform(function () {
  console.log('Process.arch: ', Process.arch)
  let envAddr = ptr(Java.vm.tryGetEnv().handle).readPointer()
  // 获取到的是JNINativeInterface 结构体

  // 0x538 是结构体偏移的指针 需要计算
  let newStringUtfAddr = envAddr.add(0x538).readPointer()
  console.log('newStringUtfAddr', newStringUtfAddr)
  if (newStringUtfAddr != null) {
    Interceptor.attach(newStringUtfAddr, {
      onEnter: function (args) {
        console.log(args[1].readCString())
      },
      onLeave: function (retval) {},
    })
  }
})
```

### 主动调用 JNI 函数

#### 使用 frida 封装的函数来调用 jni

```javascript
let funcAddr = Module.findExportByName('libxiaojianbang.so', 'helloFromC')
console.log(funcAddr)
if (funcAddr != null) {
  Interceptor.attach(funcAddr, {
    onEnter: function (args) {},
    onLeave: function (retval) {
      let env = Java.vm.tryGetEnv()
      let jstr = env.newStringUtf('bbs.125.la') //主动调用jni函数 cstr转jstr
      retval.replace(jstr)

      let cstr = env.getStringUtfChars(jstr) //主动调用 jstr转cstr
      console.log(cstr.readCString())
      console.log(hexdump(cstr))
    },
  })
}
```

#### NativeFunction 方式主动调用

```javascript
let symbols = Process.getModuleByName('libart.so').enumerateSymbols()
let newStringUtf = null
for (let i = 0; i < symbols.length; i++) {
  let symbol = symbols[i]
  if (symbol.name.indexOf('CheckJNI') == -1 && symbol.name.indexOf('NewStringUTF') != -1) {
    console.log(symbol.name, symbol.address)
    newStringUtf = symbol.address
  }
}
let newStringUtf_func = new NativeFunction(newStringUtf, 'pointer', ['pointer', 'pointer'])
let jstring = newStringUtf_func(Java.vm.tryGetEnv().handle, Memory.allocUtf8String('xiaojianbang'))
console.log(jstring)

let envAddr = Java.vm.tryGetEnv().handle.readPointer()
let GetStringUTFChars = envAddr.add(0x548).readPointer()
let GetStringUTFChars_func = new NativeFunction(GetStringUTFChars, 'pointer', ['pointer', 'pointer', 'pointer'])
let cstr = GetStringUTFChars_func(Java.vm.tryGetEnv().handle, jstring, ptr(0))
console.log(cstr.readCString())
```

### 打印函数调用堆栈

```javascript
console.log(Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n') + '\n')
```

### frida trace + IDA 插件 trace-natives 打印函数调用流程

github 地址: https://github.com/Pr0214/trace_natives

IDA -> Edit -> Plugins -> traceNatives，将会对当前 so 文件中所有函数进行 hook

使用

```sh
frida-trace -UF -O C:\Users\zeyu\Desktop\libmfw_1644263290.txt
```

会生成 `__handlers__/libdemo.so`的文件夹，里面存放对所有函数的 hook 脚本

结果如下

```
           /* TID 0x4da4 */
 11249 ms  sub_1e3c()
 11250 ms     | sub_15fc()
 11250 ms     |    | sub_1794()
 11250 ms     |    | sub_17cc()
 11250 ms     |    | sub_1804()
 11250 ms     |    | sub_184c()
 11255 ms     |    | sub_194c()
 11255 ms     |    | sub_1984()
 11255 ms     |    | sub_19c4()
 11255 ms     | sub_2140()
 11255 ms     | sub_21b0()
 11255 ms     | sub_3988()
 11255 ms     |    | sub_3a84()
 11255 ms     |    | sub_21b0()
 11255 ms     |    | sub_21b0()
 11255 ms     |    |    | sub_2428()
 11255 ms     |    |    |    | sub_3bc0()
 11255 ms     |    | sub_3a84()
 11255 ms     | sub_2004()
```

### 确认 native 函数在哪个 so

静态分析查看静态代码块中加载的 so，但并不靠谱，因为 native 函数声明在一个类中，so 加载可以在其他的类中
此外还可以在另外的类中，一次性加载所有的 so

hook 系统函数来得到绑定的 native 函数地址，然后再得到 so 地址

| 注册方式         | hook 点              |
| ---------------- | -------------------- |
| jni 函数动态注册 | hook RegisterNatives |
| jni 函数静态注册 | hook dlsym           |

#### hook_RegisterNatives

```javascript
function hook_RegisterNatives() {
  let RegisterNatives_addr = null
  let symbols = Process.findModuleByName('libart.so').enumerateSymbols()
  for (let i = 0; i < symbols.length; i++) {
    let symbol = symbols[i].name
    if (symbol.indexOf('CheckJNI') == -1 && symbol.indexOf('JNI') >= 0) {
      if (symbol.indexOf('RegisterNatives') >= 0) {
        RegisterNatives_addr = symbols[i].address
        console.log('RegisterNatives_addr: ', RegisterNatives_addr)
      }
    }
  }
  Interceptor.attach(RegisterNatives_addr, {
    onEnter: function (args) {
      let env = args[0]
      let jclass = args[1]
      let class_name = Java.vm.tryGetEnv().getClassName(jclass)
      let methods_ptr = ptr(args[2])
      let method_count = args[3].toInt32()
      console.log('RegisterNatives method counts: ', method_count)
      for (let i = 0; i < method_count; i++) {
        let name = methods_ptr
          .add(i * Process.pointerSize * 3)
          .readPointer()
          .readCString()
        let sig = methods_ptr
          .add(i * Process.pointerSize * 3 + Process.pointerSize)
          .readPointer()
          .readCString()
        let fnPtr_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer()
        let find_module = Process.findModuleByAddress(fnPtr_ptr)
        console.log(
          'RegisterNatives java_class: ',
          class_name,
          'name: ',
          name,
          'sig: ',
          sig,
          'fnPtr: ',
          fnPtr_ptr,
          'module_name: ',
          find_module.name,
          'module_base: ',
          find_module.base,
          'offset: ',
          ptr(fnPtr_ptr).sub(find_module.base),
        )
      }
    },
    onLeave: function (retval) {},
  })
}
```

#### hook_dlsym

```javascript
function hook_dlsym() {
  let dlsymAddr = Module.findExportByName('libdl.so', 'dlsym')
  console.log(dlsymAddr)
  Interceptor.attach(dlsymAddr, {
    onEnter: function (args) {
      this.args1 = args[1]
    },
    onLeave: function (retval) {
      let module = Process.findModuleByAddress(retval)
      if (module == null) return
      console.log(this.args1.readCString(), module.name, retval, retval.sub(module.base))
    },
  })
}
```

### inlineHook（针对寄存器的值）

```javascript
function inlineHook() {
  // var nativePointer = Module.findBaseAddress("libxiaojianbang.so");
  // var hookAddr = nativePointer.add(0x17BC);
  // Interceptor.attach(hookAddr, {
  //     onEnter: function (args) {
  //         console.log("onEnter: ", this.context.x8);
  //     }, onLeave: function (retval) {
  //         console.log("onLeave: ", this.context.x8.toInt32());
  //         console.log(this.context.x8 & 7);
  //     }
  // });

  var nativePointer = Module.findBaseAddress('libxiaojianbang.so')
  var hookAddr = nativePointer.add(0x1b70)
  Interceptor.attach(hookAddr, {
    onEnter: function (args) {
      console.log('onEnter: ', this.context.x1)
      console.log('onEnter: ', hexdump(this.context.x1))
    },
    onLeave: function (retval) {},
  })
}
```

### hook_dlopen

有些函数在 so 首次加载的时候执行，而 so 没加载之前又不能去 hook，那么要 hook 这些函数，就必须监控 so 何时被加载，因此，需要 hook dlopen 等系统函数，当 so 加载完毕，立刻 hook

```javascript
//hook_dlopen
function hook_dlopen(addr, soName, callback) {
  Interceptor.attach(addr, {
    onEnter: function (args) {
      let soPath = args[0].readCString()
      if (soPath.indexOf(soName) != -1) this.hook = true
    },
    onLeave: function (retval) {
      if (this.hook) callback()
    },
  })
}

function hook_func() {
  let baseAddr = Module.findBaseAddress('libxiaojianbang.so')
  console.log('baseAddr', baseAddr)
  let MD5Final = baseAddr.add(0x3540)
  Interceptor.attach(MD5Final, {
    onEnter: function (args) {
      this.args1 = args[1]
    },
    onLeave: function (retval) {
      console.log(hexdump(this.args1))
    },
  })
}

let dlopen = Module.findExportByName('libdl.so', 'dlopen') // 低版本安卓系统
let android_dlopen_ext = Module.findExportByName('libdl.so', 'android_dlopen_ext') // 高版本安卓系统
//console.log(JSON.stringify(Process.getModuleByAddress(dlopen)));
hook_dlopen(dlopen, 'libxiaojianbang.so', hook_func)
hook_dlopen(android_dlopen_ext, 'libxiaojianbang.so', hook_func)
```

### hook_initarray

```javascript
function main() {
  function hook_dlopen(addr, soName, callback) {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        var soPath = args[0].readCString()
        if (soPath.indexOf(soName) != -1) hook_call_constructors()
      },
      onLeave: function (retval) {},
    })
  }
  var dlopen = Module.findExportByName('libdl.so', 'dlopen')
  var android_dlopen_ext = Module.findExportByName('libdl.so', 'android_dlopen_ext')
  hook_dlopen(dlopen, 'libxiaojianbang.so', inlineHook)
  hook_dlopen(android_dlopen_ext, 'libxiaojianbang.so', inlineHook)

  var isHooked = false
  function hook_call_constructors() {
    var symbols = Process.getModuleByName('linker64').enumerateSymbols()
    var call_constructors_addr = null
    for (let i = 0; i < symbols.length; i++) {
      var symbol = symbols[i]
      // initarray 在__dl__ZN6soinfo17call_constructorsEv中被调用的
      if (symbol.name.indexOf('__dl__ZN6soinfo17call_constructorsEv') != -1) {
        call_constructors_addr = symbol.address
      }
    }
    console.log('call_constructors_addr: ', call_constructors_addr)
    Interceptor.attach(call_constructors_addr, {
      onEnter: function (args) {
        if (!isHooked) {
          hook_initarray()
          isHooked = true
        }
      },
      onLeave: function (retval) {},
    })
  }

  function hook_initarray() {
    var xiaojianbangAddr = Module.findBaseAddress('libxiaojianbang.so')
    var func1_addr = xiaojianbangAddr.add(0x1c54)
    var func2_addr = xiaojianbangAddr.add(0x1c7c)

    Interceptor.replace(
      func1_addr,
      new NativeCallback(
        function () {
          console.log('func1 is replaced!!!')
        },
        'void',
        [],
      ),
    )

    Interceptor.replace(
      func2_addr,
      new NativeCallback(
        function () {
          console.log('func2 is replaced!!!')
        },
        'void',
        [],
      ),
    )
  }
}
main()
```

### hook_JNIOnload

```javascript
hook_dlopen(dlopen, 'libxiaojianbang.so', hook_JNIOnload)
hook_dlopen(android_dlopen_ext, 'libxiaojianbang.so', hook_JNIOnload)

function hook_JNIOnload() {
  var xiaojianbangAddr = Module.findBaseAddress('libxiaojianbang.so')
  // 0x1CCC JNIOnload的地址
  var funcAddr = xiaojianbangAddr.add(0x1ccc)
  Interceptor.replace(
    funcAddr,
    new NativeCallback(
      function () {
        console.log('this func is replaced !')
      },
      'void',
      [],
    ),
  )
}
```

### hook_pthread_create

创建子线程的相关函数

```javascript
function hook_pthread_create() {
  var pthread_create_addr = Module.findExportByName('libc.so', 'pthread_create')
  console.log('pthread_create_addr: ', pthread_create_addr)
  Interceptor.attach(pthread_create_addr, {
    onEnter: function (args) {
      console.log(args[0], args[1], args[2], args[3])
      var Module = Process.findModuleByAddress(args[2])
      if (Module != null) console.log(Module.name, args[2].sub(Module.base))
    },
    onLeave: function (retval) {},
  })
}
hook_pthread_create()
```

## 封装 so 中常用 hook 函数

```javascript
function showStacks() {
  console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n')
}

function findJNIFunc(func) {
  if (!func) return null
  let artSym = Module.enumerateSymbols('libart.so')
  for (const sym of artSym) {
    if (!sym.name.includes('CheckJNI') && sym.name.includes(func)) {
      // console.log(JSON.stringify(sym));
      return sym.address
    }
  }
  return null
}

function hookNewStringUTF() {
  // 找到 env->NewStringUTF(a1, str) 函数
  const NewStringUTFAddr = findJNIFunc('NewStringUTF')
  // console.log('NewStringUTFAddr', NewStringUTFAddr);
  if (NewStringUTFAddr !== null) {
    Interceptor.attach(NewStringUTFAddr, {
      onEnter: function (args) {
        showStacks.call(this)
        console.log(args[1].readCString())
      },
      onLeave: function (retval) {},
    })
  }
}

function hookNewByteArray() {
  const NewByteArrayAddr = findJNIFunc('NewByteArray')
  console.log('NewByteArrayAddr', NewByteArrayAddr)
  if (NewByteArrayAddr !== null) {
    Interceptor.attach(NewByteArrayAddr, {
      onEnter: function (args) {
        showStacks.call(this)
        console.log(args[1].toInt32())
      },
      onLeave: function (retval) {
        // retval 返回的是一个java对象,不可直接读取,需要将其转为c中的指针
        // 得到是一个 NativePointer
        // let retPointer = Java.vm.tryGetEnv().getByteArrayElements(retval);
        // console.log(retPointer.readByteArray(32));
      },
    })
  }
}

function print_arg(addr) {
  var module = Process.findRangeByAddress(addr)
  if (module != null) return '\n' + hexdump(addr)
  return ptr(addr)
}

function hook_native_addr(funcPtr, params = [], result = {}) {
  var module = Process.findModuleByAddress(funcPtr)
  Interceptor.attach(funcPtr, {
    onEnter: function (args) {
      this.logs = []
      this.args = []
      this.logs.push('call ' + module.name + '!' + ptr(funcPtr).sub(module.base))
      for (let i = 0; i < params.length; i++) {
        let param = params[i]
        this.args.push(args[i])
        if (param.type) {
          this.logs.push(`a${i + 1} onEnter:` + args[i][param.type]())
        } else {
          this.logs.push(`a${i + 1} onEnter:` + print_arg(args[i]))
        }
      }
    },
    onLeave: function (retval) {
      for (let i = 0; i < params.length; i++) {
        let param = params[i]
        if (param.type) {
          this.logs.push(`a${i + 1} onLeave:` + this.args[i][param.type]())
        } else {
          this.logs.push(`a${i + 1} onLeave:` + print_arg(this.args[i]))
        }
      }
      if (result.type) {
        this.logs.push('retval onLeave: ' + retval[result.type]())
      } else {
        this.logs.push('retval onLeave: ' + print_arg(retval))
      }
      console.log(this.logs.join('\n'))
    },
  })
}

// ================================================================================

// hookNewStringUTF() // 用于定位NewStringUTF
// hookNewByteArray(); // 用于定位NewByteArray

const moduleName = 'libnative-lib.so'
let baseAddr = Module.findBaseAddress(moduleName)

// let sub_1234 = baseAddr.add(0x1234 + 1);
// hook_native_addr(sub_1234, Array(3).fill({}));
```

## JNItrace

so 中会应用很多的 jni 函数，比如：Java 的字符串到 C，需要先使用 GetStringUtfChars 来转成 C 语言字符串。
而加密后的结果，如果要转成 jstring，又需要用到 NewStringUtf，所以可以通过 hook 这些 jni 函数，来可以定位关键代码，也可以大体上了解函数的代码逻辑。

**jnitrace 就是 hook 一系列的 jni 函数**

github 地址：https://github.com/chame1eon/jnitrace

版本: jnitrace-3.3.0

### 安装（进入到 frida 环境）

```sh
pip install jnitrace
```

### 使用

```sh
jnitrace -m attach -l <模块.so> <包名>
```

-m <spawn|attach> 附加方式去运行

-o path/output.json 将结果输出到文件上

## ollvm 字符串解密

找到加密的字符串地址(基址+变量偏移地址)，通过 hexdump 可以直接打印出内存中解密后的状态

使用 JNItrace，但是前提只能查看 jni 相关函数

从内存中 dump 整个 so，获取所有解密后的字符串，但是需要修复

分析 so 中字符串解密函数，然后还原（同 js 混淆解密函数）

### dump_so.js

```javascript
function dump_so(so_name) {
  Java.perform(function () {
    let currentApplication = Java.use('android.app.ActivityThread').currentApplication()
    let dir = currentApplication.getApplicationContext().getFilesDir().getPath()
    let libso = Process.getModuleByName(so_name)
    console.log('[name]:', libso.name)
    console.log('[base]:', libso.base)
    console.log('[size]:', ptr(libso.size))
    console.log('[path]:', libso.path)
    let file_path = dir + '/' + libso.name + '_' + libso.base + '_' + ptr(libso.size) + '.so'
    let file_handle = new File(file_path, 'wb')
    if (file_handle && file_handle != null) {
      Memory.protect(ptr(libso.base), libso.size, 'rwx')
      let libso_buffer = ptr(libso.base).readByteArray(libso.size)
      file_handle.write(libso_buffer)
      file_handle.flush()
      file_handle.close()
      console.log('[dump]:', file_path)
    }
  })
}
```

使用 dump_so(so_name)将保存的文件拉去到桌面上（需要先从私有目录移动到权限大的目录下再移动到桌面）。

此时的 so 文件直接通过 IDA 打开会报错，需要修复，使用的工具是[SoFixer](https://github.com/F8LEFT/SoFixer)。

### SoFixer

github 地址：[F8LEFT/SoFixer (github.com)](https://github.com/F8LEFT/SoFixer)

使用方式详看 README

注: 修复后的 so 文件无法重新打包动态分析，只可静态分析使用

## Frida 检测

[翻译多种特征检测 Frida-外文翻译-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-217482.htm)

#### ptrace 占坑

ptrace(0, 0 ,0 ,0);
开启一个子进程附加父进程，通常有一下几种

- 守护进程
- 子进程附加父进程 目的是不让别人附加
- 普通的多进程

就只好使用 frida -f 包名 spawn 方式启动

#### 进程名检测

遍历运行的进程列表，检测 frida-server 是否运行

#### 端口检测

检测 frida-server 默认端口 27042 是否开放

#### D-Bus 协议通信

app 运行时，会创建/proc/进程 pid 的文件夹

Frida 使用 D-Bus 协议通信，可以遍历/proc/net/tcp 文件，或者直接从 0-65535
向每个开放的端口发送 D-Bus 认证消息，哪个端口回复了 REJECT，就是 frida-server

#### 扫描 maps 文件

cat maps

maps 文件用于显示当前 app 中加载的依赖库
Frida 在运行时会先确定路径下是否有 re.frida.server 文件夹
若没有则创建该文件夹并存放 frida-agent.so 等文件，该 so 会出现在 maps 文件中

#### 扫描 task 目录

扫描目录下所有/task/pid/status 中的 Name 字段
寻找是否存在 frida 注入的特征
具体线程名为 gmain、gdbus、gum-js-loop、pool-frida 等

#### 通过 readlink

查看/proc/self/fd、/proc/self/task/pid/fd 下所有打开的文件，检测是否有 Frida 相关文件

#### 常见用于检测的系统函数

strstr、strcmp、open、read、fread、readlink

扫描内存中是否有 Frida 库特征出现，例如字符串 LIBFRIDA

#### 通常比较会被检测的文件

riru 的特征文件
/system/lib/libmemtrack.so
/system/lib/libmemtrack_real.so
cmdline 检测进程名，防重打包
status 检测进程是否被附加
stat 检测进程是否被附加
task/xxx/cmdline 检测进程名，防重打包
task/xxx/stat 检测进程是否被附加
task/xxx/status 检测线程 name 是否包含 Frida 关键字
fd/xxx 检测 app 是否打开的 Frida 相关文件
maps 检测 app 是否加载的依赖库里是否有 Frida
net/tcp 检测 app 打开的端口

huluda-server 处理了 re.frida.server 文件夹以及该文件夹下的文件的名字

使用这个 server，不放在/data/local/tmp 目录下，基本可以不用关心 fd 和 maps 的检测

frida-gadget https://bbs.pediy.com/thread-269866.htm
