---
title: Pinia
date: 2020-10-23
authors: kuizuo
tags: [vue]
---

<!-- truncate -->

> 官方文档：[Introduction | Pinia (vuejs.org)](https://pinia.vuejs.org/introduction.html)

## 安装

```sh
npm install pinia
```

## 创建 Store

在 src/store 中创建 index.ts，并导出 store

```typescript title="src/store/index.ts"
import { createPinia } from 'pinia'

const store = createPinia()

export default store 
```

在 main.ts 中引入并使用

```typescript title="main.ts"
import { createApp } from 'vue'
import App from './App.vue'
import store from './store'

const app = createApp(App)
app.use(store)
```

## 创建 modules

在 src/store 目录下创建 modules 目录，里面存放项目中所需要使用到的状态。演示代码如下

```typescript title="store/modules/user.ts"
import { defineStore } from 'pinia'

interface UserState {
	name: string
}

export const useUserStore = defineStore({
	id: 'user',
	state: (): UserState => {
		return {
			name: 'kuizuo'
		}
	},
	getters: {
		getName(): string {
			return this.name
		}
	},
	actions: {
		setName(name: string) {
			this.name = name
		}
	}
})
```

## 使用

### 获取state

```vue
<template>
  <div>{{ userStore.name }}</div>
</template>

<script lang="ts" setup>
import { useUserStore } from '/@/store/modules/user'

const userStore = useUserStore()
</script>
```

不过这样写法不优雅，就可以使用 computed

```typescript
const name = computed(() => userStore.getName) // 前提定义了getters
const name = computed(() => userStore.name)
```

state 也可以使用解构，但使用解构会使其失去响应式，这时候可以用 pinia 的 `storeToRefs`。

```typescript
import { storeToRefs } from 'pinia'
const { name } = storeToRefs(userStore)
```

### 修改state

可以直接使用`userStore.name = "xxx"` 来进行修改，但不建议，而是使用actions来修改，在上面已经定义一个setName方法用来修改state

```typescript
userStore.setName('xxx')
```

## 与vuex对比

不难发现，pinia比vuex少了个`mutations`，也就是变更状态的函数，而pinia则是将其与action合并在一起。

在Vuex中mutation是无法异步操作的，而Action可以包含任意异步操作。像上面要写异步操作的只需要在actions中正常的编写async await语法的异步函数即可。如

```typescript
export const useUserStore = defineStore({
  id: 'user',
  actions: {
    async login(user) {
      const { data } = await api.login(user)
      return data
    }
  }
})
```

而vuex中写法与调用就不堪入目了😂

## 数据持久化

安装

```sh
npm i pinia-plugin-persist
```

使用

```typescript {2,5}
import { createPinia } from 'pinia'
import piniaPluginPersist from 'pinia-plugin-persist'

const store = createPinia()
store.use(piniaPluginPersist)

export default store
```

在对应的store中开启persist即可，**默认情况下数据是存放在sessionStorage(会话存储)，并以store中的id作为key**

```typescript {8-10}
export const useUserStore = defineStore({
	id: 'user',
	state: (): UserState => {
		return {
			name: 'kuizuo'
		}
	},
	persist: {
		enabled: true
	}
})
```

persist还有其他配置，例如自定义key，存放位置改为localStorage

```typescript {3-8}
persist: {
	enabled: true,
	strategies: [
		{
			key: 'my_user',
			storage: localStorage
		}
	]
}
```

还可以使用paths来指定那些state持久化，如下

```typescript {5}
persist: {
  enabled: true,
  strategies: [
    {
      paths: ['name']
    }
  ]
}
```
