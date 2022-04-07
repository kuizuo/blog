---
title: Frida Python库使用
date: 2021-02-10
authors: kuizuo
tags: [frida,app,hook]
---

<!-- truncate -->

## 启动Frida服务

### 包名附加

```python
import frida, sys

jsCode = """ ...... """
process = frida.get_usb_device().attach('com.dodonew.online')
script = process.create_script(jsCode)
script.load()
sys.stdin.read()
```

### pid附加

```python
process = frida.get_usb_device().attach(1234) # 1234 pid 
```

### spawn方式启动

```python
device = frida.get_usb_device()
pid = device.spawn(["com.dodonew.online"])    # 以挂起方式创建进程
process = device.attach(pid)
script = process.create_script(jsCode)
script.load()
device.resume(pid)  # 加载完脚本, 恢复进程运行
sys.stdin.read()
```

### 连接非标准端口

```python
process = frida.get_device_manager().add_remote_device('192.168.3.68:8888').attach('com.dodonew.online')
```

### 连接多个设备

```python
process = frida.get_device_manager().add_remote_device('192.168.3.68:8888').attach('com.dodonew.online')
script = process.create_script(jsCode)
script.load()
process1 = frida.get_device_manager().add_remote_device('192.168.3.69:8888').attach('com.dodonew.online')
script1 = process.create_script(jsCode)
script1.load()
sys.stdin.read()
```

## frida与Python的交互

```python {7-12,17}
# -*- coding: UTF-8 -*-
import frida, sys

jsCode = """"""


def onMessage(message, data):
    # print(message) 
    # {'type': 'send', 'payload':'some strings'}
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)


process = frida.get_usb_device().attach('com.dodonew.online')
script = process.create_script(jsCode)
script.on('message', onMessage)
script.load()
sys.stdin.read()
```

在jscode中可以使用`send(data)`，将数据传入到onMessage回调函数中处理。

### recv与script.post

在js端中可以通过send向python发送数据，而python要向js发送数据则需要使用script.post，js中使用recv来接收，演示代码如下

```python {8-11,23-24}
jsCode = """
    Java.perform(function(){
        var Utils = Java.use('com.dodonew.online.util.Utils');
        Utils.md5.implementation = function(a){
            console.log('MD5 string: ', a);
            var retval = this.md5(a);
            send(retval);
            recv(function(obj){
                console.log(JSON.stringify(obj));
                retval = obj.data;
            }).wait();
            return retval;
        }
    });
"""


def onMessage(message, data):
   print(message)
   if message["type"] == 'send':
       print(u"[*] {0}".format(message['payload']))
       time.sleep(10)
       script.post({"data": "a123456"})
   else:
       print(message)
```

##  算法转发

### rpc.exports与script.exports

js端：`rpc.exports = { func: func}`

python端：`script.exports.func()/script.exports.FUNC()`

注: 如果js导出函数中包含驼峰命名，则python需要将大写替换成_小写，如getUser => get_user

```python

jsCode = """
    function md5(data){
        var result = "";
        Java.perform(function(){
            result = Java.use('com.dodonew.online.util.Utils').md5(data);
        });
        return result;
    }
    
    rpc.exports = {
        md5: md5
    };
"""


result = script.exports.md5('a123456')
print(result)
```

### 使用fastapi搭建接口

```python
from fastapi import FastAPI
import uvicorn
import frida

jsCode = """
    function enc(data){
        var result;
        Java.perform(function(){
			// 主动调用难以复现的加密算法,将结果返回
            result = "a123456" + data;
        });
        return result;
    }
    rpc.exports = {
        enc: enc
    };
"""

process = frida.get_device_manager().add_remote_device('192.168.3.68:27042').attach("com.dodonew.online")
script = process.create_script(jsCode)
script.load()


app = FastAPI()

@app.get("/getEnc")
async def getEnc(username=None, password=None):
    result = script.exports.enc({username: username, password: password})
    return {"result": result}

class Item(BaseModel):
    username: str = None
    password: str = None

@app.post("/getEnc")
async def getEncPost(postData: Item):
    result = script.exports.enc(postData)
    return {"result": result}

if __name__ == '__main__':
    uvicorn.run(app, port = 8080)

```

http发送get请求 如 http://127.0.0.1:8080/getEnc?username=kuizuo&password=a123456，即可得到enc调用后的结果，post请求同理