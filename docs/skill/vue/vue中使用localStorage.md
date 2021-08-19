---
title: 使用localStorage本地记录用户账号密码
date: 2020-12-11
tags:
  - vue
---

## 前言

先说用途，利用浏览器内的的localStorage来保存用户的账号密码，下次登录自动将其显示在表单上。

这里所采用的是是Vue框架来实现

## :pencil:代码

```vue
<template>
  <div>
    <el-form :model="form">
      <el-form-item label="账号" prop="username">
        <el-input v-model="form.username" />
      </el-form-item>
      <el-form-item label="密码" prop="password">
        <el-input v-model="form.password" type="password" show-password />
      </el-form-item>
      <el-button @click="handleLogin">登录</el-button>
    </el-form>
  </div>
</template>

<script>
export default {
  data() {
    return {
      form: { username: '', password: '' },
    };
  },
  created() {
    this.form = JSON.parse(localStorage.getItem('user')) || { };
  },
  methods: {
    handleLogin() {
        localStorage.setItem('user', JSON.stringify(this.form));
    },
  },
};
</script>
```

简单一看，貌似还挺简单的。随便输入一个账号密码来演示一下。在控制台中可以看到我刚刚输入的账号密码已经给保存到了localStorage上。

![image-20201211014505500](https://img.kuizuo.cn/image-20201211014505500.png)

此时我退出，重新运行一遍，此时对应的数据将显示在对应的表单上

![image-20201211014715960](https://img.kuizuo.cn/image-20201211014715960.png)

就是这么简单。此外要保存其他持续化数据（页面配置，用户信息等等）同样也可以通过localStorage来实现。

## 使用方法

### 保存

如果保存的是一个对象，可以将其转化为JSON格式（`JSON.stringify(obj)`）来存储

```js
localStorage.setItem('key', 'value');
localStorage.setItem('info', JSON.stringify(info));
```

### 获取

如果要获取的是一个JSON格式数据，通过`JSON.parse(json)`来解析为js对象。

```js
localStorage.setItem('key');
JSON.parse(localStorage.getItem('info'));
```

### 删除

```js
// 删除某个
localStorage.setItem('key');

// 删除所有
localStorage.clear();
```

### 监听

```js
// Storage 发生变化（增加、更新、删除）时的 触发，同一个页面发生的改变不会触发，只会监听同一域名下其他页面改变 Storage
window.addEventListener('storage', function (e) {
	console.log('key', e.key);
	console.log('oldValue', e.oldValue);
	console.log('newValue', e.newValue); 
	console.log('url', e.url);
}
```

## 注意

localStorage有效期是永久的，一般的浏览器能存储的是5MB左右。

sessionStorage默认的有效期是浏览器的会话时间（也就是说标签页关闭后就消失了）。
localStorage作用域是协议、主机名、端口。（理论上，不人为的删除，会一直存在设备中）
sessionStorage作用域是窗口、协议、主机名、端口。

在vue中 可直接使用localStorage，因为localStorage是window上的。所以不需要写this.localStorage。