---
title: JavaScript存储与操作二进制数据
date: 2022-01-24
authors: kuizuo
tags: [js]
---

在我编写js代码中，关于处理二进制数据了解甚少，好像都是用数组表示，但是成员又很模糊。尤其是在遇到一些http的post请求或websocket，发送二进制数据（字节）时，还有一些算法的翻译，数据的转化，协议的复现，都需要不断的从网络上查阅，并未系统的从文档教程中入手。于是写这篇的目的就是为了加固对二进制数据的理解，以及JavaScript中如何操作二进制数据的。

<!-- truncate -->

## ArrayBuffer 

其他语言java，易所表示的是字节数组，字节集，而在js中则称二进制数组（都是用来表示二进制数据的），要注意的是这里的二进制数组并不是真正的数组，而是类似数组的对象。（后文会提到）

存储二进制数据用到的就是`ArrayBuffer`，但 `ArrayBuffer`不能直接读写，只能存储，需要通过视图来进行操作。

例如存储二进制数据的则是ArrayBuffer对象，例如请求图片时，就会指定参数 `responseType: 'arraybuffer'`表示返回二进制数据，也就是图片数据。

`ArrayBuffer`也是一个构造函数，可以分配一段可以存放数据的连续内存区域。

```javascript
const buffer = new ArrayBuffer(8);
```

```javascript
ArrayBuffer {
  [Uint8Contents]: <00 00 00 00 00 00 00 00>,
  byteLength: 8
}
```

这里的buffer.byteLength属性用于获取字节长度（返回32），直接打印buf的结果

其中还有一个`slice`方法，允许将内存区域的一部分，拷贝生成一个新的`ArrayBuffer`对象。下面代码拷贝`buffer`对象的前 3 个字节（从 0 开始，到第 3 个字节前面结束）

```javascript
const buffer = new ArrayBuffer(8);
const newBuffer = buffer.slice(0, 3);
```

除了`slice`方法，`ArrayBuffer`对象不提供任何直接读写内存的方法，只允许在其上方建立视图，然后通过视图读写。

## TypedArray

不过只有空数据可没用，肯定需要操作`ArrayBuffer`，也就要介绍下`TypedArray`。

`ArrayBuffer`对象作为内存区域，可以存放多种类型的数据。同一段内存，不同数据有不同的解读方式，这就叫做“视图”（view），`ArrayBuffer`有两种视图，一种是`TypedArray`视图，另一种是`DataView`视图。这里只介绍`TypedArray`

`TypedArray`视图一共包括 9 种类型，每一种视图都是一种构造函数通过9个构造函数，可以生成9种数据格式的视图，比如`Uint8Array`（无符号8位整数，表示一个字节）数组视图，具体如下

| 数据类型 | 字节长度 | 含义                            | 对应的C语言类型 |
| :------- | :------- | :------------------------------ | :-------------- |
| Int8     | 1        | 8位带符号整数                   | signed char     |
| Uint8    | 1        | 8位不带符号整数                 | unsigned char   |
| Uint8C   | 1        | 8位不带符号整数（自动过滤溢出） | unsigned char   |
| Int16    | 2        | 16位带符号整数                  | short           |
| Uint16   | 2        | 16位不带符号整数                | unsigned short  |
| Int32    | 4        | 32位带符号整数                  | int             |
| Uint32   | 4        | 32位不带符号的整数              | unsigned int    |
| Float32  | 4        | 32位浮点数                      | float           |
| Float64  | 8        | 64位浮点数                      | double          |

视图的构造函数可以接受三个参数：

- 第一个参数（必需）：视图对应的底层`ArrayBuffer`对象。
- 第二个参数（可选）：视图开始的字节序号，默认从 0 开始。
- 第三个参数（可选）：视图包含的数据个数，默认直到本段内存区域结束。

演示

不妨给它写入字符串abc，对应的十进制ASCII码为97,98,99，由于ASCII码占用一个字节存储，所以这里选择Uint8Array用于表示

```javascript
const buffer = new ArrayBuffer(8);
const buf = new Uint8Array(buffer);
buf.set([97, 98, 99]);
console.log(buf.buffer); 

// 输出结果
ArrayBuffer {
  [Uint8Contents]: <61 62 63 00 00 00 00 00>,
  byteLength: 8
}
```

可以看到abc确实存入了，并用十六进制的形式表示，为了验证，这里使用NodeJS中的Buffer来演示，当然也可以使用原生的[TextEncoder](https://es6.ruanyifeng.com/#docs/arraybuffer#ArrayBuffer-%E4%B8%8E%E5%AD%97%E7%AC%A6%E4%B8%B2%E7%9A%84%E4%BA%92%E7%9B%B8%E8%BD%AC%E6%8D%A2)

```javascript
Buffer.from(buf.buffer).toString() // abc
```

你也可以直接通过数组下标的形式，来访问数据，如`buf[0]`返回的就是97，但buf又有length与其他的属性方法，这种数组就统称为类数组。

buf还有一些方法，无非就是操作字节复制，偏移就不做过多介绍与演示了，具体可查看[文档](https://es6.ruanyifeng.com/#docs/arraybuffer)

## NodeJS的Buffer

[buffer 缓冲区 | Node.js API 文档 (nodejs.cn)](http://nodejs.cn/api/buffer.html#buffer_buffers_and_character_encodings)

在Nodejs中有专门的操作`ArrayBuffer` 的对象`Buffer`，`Buffer` 类是 JavaScript [`Uint8Array`](http://url.nodejs.cn/ZbDkpm) 类的子类

所以`Uint8Array`有的属性方法Buffer也有，不过Nodejs对Buffer增加了额外的方法供开发者调用。

### [Buffer.from](http://nodejs.cn/api/buffer.html#static-method-bufferfromarray)

上面的代码 `Buffer.from(buf.buffer).toString()`，也就是将`ArrayBuffer` 数据转为utf8编码文本。其中toString还能转为以下编码（toString默认utf8）

```typescript
type BufferEncoding = 'ascii' | 'utf8' | 'utf-8' | 'utf16le' | 'ucs2' | 'ucs-2' | 'base64' | 'base64url' | 'latin1' | 'binary' | 'hex';
```

不过Nodejs不支持gbk编码，所以需要使用第三方包，如iconv-lite

`Buffer.from()`有多个方法实现，第一个参数可以传入ArrayBuffer | Uint8Array | string，如果是string类型，第二个参数为编码格式，例如实现编码转化

```javascript
// base64
Buffer.from(str).toString('base64'); // 将str转base64编码
Buffer.from(str, 'base64').toString(); // 将base64编码转str

// hex
Buffer.from(str).toString('hex');  // 将str转hex编码
Buffer.from(str, 'hex').toString(); // 将hex编码转str
```

封装Base64编码与解码

```javascript
const Base64 = {
  encode: (str) => {
    return Buffer.from(str).toString('base64');
  },
  decode: (str) => {
    return Buffer.from(str, 'base64').toString();
  }
}
```

### [buf.toJSON()](http://nodejs.cn/api/buffer.html#buftojson)

将会得到buf的视图类型，与二进制数组。

```javascript
// let buf = Buffer.from('abc');
let buf = Buffer.from([97,98,99]);
console.log(buf); // <Buffer 61 62 63>

buf.toJSON() // { type: 'Buffer', data: [ 97, 98, 99 ] }
// 效果等同于 JSON.stringify(buf);

buf.values() // [ 97, 98, 99 ]   可以直接得到二进制数据
```

官方文档: [buffer 缓冲区 | Node.js API 文档 (nodejs.cn)](http://nodejs.cn/api/buffer.html#buffer)

## ArrayBuffer 和 Buffer 区别

上述对这两者进行了介绍，这里总结一下

`ArrayBuffer` 对象用来表示通用的、固定长度的原始二进制数据缓冲区，是一个字节数组，可读但不可直接写。

`Buffer` 是 Node.JS 中用于操作 `ArrayBuffer` 的视图，继承自`Uint8Array`，是 `TypedArray` 的一种。

通俗点来说（**对我而言**），`ArrayBuffer`相当于其他语言的字节数组、字节集，但不可写，而`Buffer` 对象则是操作`ArrayBuffer`的。

## 应用

与二进制数据有关的地方就有应用

### 编码转化

### 将请求图片转化成base64编码

```javascript
axios
  .get('图片url地址', {
    responseType: 'arraybuffer',
  })
  .then((res) => {
    let base64Img = res.data.toString('base64');
    console.log(base64Img);
  });
```

在axios请求图片数据的时候，指定`responseType: 'arraybuffer'`，返回的data就是一个buffer对象。（当时写成这样的代码 `Buffer.from(res.data).buffer`，不过不妨碍）

### http发送二进制数据与WebSocket

```javascript
axios.post('http://example.com', Buffer.from('abc')).then((res) => {
  console.log(res.data);
});
```

```javascript
let socket = new WebSocket('ws://127.0.0.1:8081');
socket.binaryType = 'arraybuffer';

// Wait until socket is open
socket.addEventListener('open', function (event) {
  // Send binary data
  const typedArray = new Uint8Array(4);
  socket.send(typedArray.buffer);
});

// Receive binary data
socket.addEventListener('message', function (event) {
  const arrayBuffer = event.data;
  // ···
});
```

### 文件读写

等等。。。

## 参考

> [ArrayBuffer - ECMAScript 6入门 (ruanyifeng.com)](https://es6.ruanyifeng.com/#docs/arraybuffer)
>
> [ArrayBuffer 和 Buffer 有何区别？ - 知乎 (zhihu.com)](https://www.zhihu.com/question/26246195/answer/1231680251#ref_1)

