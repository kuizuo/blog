---
id: vue-component
title: Vue组件
date: 2020-10-23
authors: kuizuo
tags: [vue]
keywords: [vue]
---

<!-- truncate -->

如果一个页面，包含导航栏，侧边栏，主体，底部等等，如果将这些全部写在一个 html 代码，万一侧边栏出了问题，维护起来将非常不方便。但如果将上面这些细分成一个个小的模块组件，比如导航栏内有搜索栏和 logo，就可以将这两个在细分为模块组件，这就是组件化开发。

![组件化](https://cn.vuejs.org/images/components.png)

通过组件化的方式，可以让每个组件之间互不干扰，并且方便引入和导出。下面是 vue 创建组件的一个例子：

```vue
// 定义一个名为 button-counter 的新组件(全局组件) Vue.component('button-counter', { data: function () { return { count: 0 } }, template: '
<button v-on:click="count++">You clicked me {{ count }} times.</button>
' })
```

但需要组件注册使用，如

```vue
let buttonCounter = Vue.component(...) var app = new Vue（{ el: "#app", components:{ buttonCounter } }
```

组件是可复用的 Vue 实例，且带有一个名字：在这个例子中是 `<button-counter>`。我们可以在一个通过 `new Vue` 创建的 Vue 根实例中，把这个组件作为自定义元素来使用：

```vue
<div id="components-demo">
  <button-counter></button-counter>
  <button-counter></button-counter>
</div>
```

### data 必须是一个函数，而不是一个对象

对于**组件化开发**，**一个组件的 `data` 选项必须是一个函数**，原因很简单，如果组件复用的话则会公用 data 对象的值，所以写成下面的形式**通过函数返回一个对象，而不是定义一个对象**。

```vue
data: function () { return { count: 0 } }
```

当然，如果你想引用该组件是绑定公用属性也不是说不行。

### 组件名大小写

定义组件名的方式有两种：

- 使用 kebab-case

通过**-**分隔命名，当使用 kebab-case (短横线分隔命名) 定义一个组件时，你也必须在引用这个自定义元素时使用 kebab-case，例如 `<my-component-name>`。

```
Vue.component('my-component-name', { /* ... */ })
```

- 使用 PascalCase

通过**首字母大写**命名分隔命名，当使用 PascalCase (首字母大写命名) 定义一个组件时，你在引用这个自定义元素时两种命名法都可以使用。也就是说 `<my-component-name>` 和 `<MyComponentName>` 都是可接受的。

```
Vue.component('MyComponentName', { /* ... */ })
```

**注，尽管如此，直接在 DOM (即非字符串的模板) 中使用时只有 kebab-case 是有效的**。也就是在视图面板中，还是得用-分隔命名。比如有个 UserCard 组件，那么就应该这样写

```vue
<template>
  <div>
    <user-card></user-card>
  </div>
</template>

<script>
import UserCard from "./components/UserCard";

export default {
  components: { UserCard },
</script>
```

### 脚手架开发

但一般来说都是通过脚手架来开发 Vue 的，也就是说上面那些没必要深入了解，而下面就需要了。一般的项目结构如下：

![image-20200921170240661](https://img.kuizuo.cn/image-20200921170240661.png)

其中 src 是源目录，这里使我们开发的时候用到的地方，App.vue 是入口文件，而 components 是放置上面所的组件地方，一般是以大写字母开头.vue 结尾。比如我这个 vue 项目是做一个简单的聊天界面，那么我需要聊天框和用户列表框，那我就在 components 下创建两个文件`Chat.vue`和`Userlist.vue`（组件首字母大写），而这两个都是组件，其内容一般分为三个部分：

```vue
<template></template>

<script>
export default {}
</script>

<style></style>
```

- template 模板
- script 数据交互
- style 样式

而在 App.vue 中，我就可以将这两个组件导入，并且使用。

```vue
<template>
  <div id="app">
    <chat></chat>
    <user-list></user-list>
  </div>
</template>

<script>
import Chat from '@/components/Chat'
import UserList from '@/components/UserList'

export default {
  name: 'App',
  components: {
    Chat,
    UserList,
  },
}
</script>
```

**路径下的@指的是 src 这个目录。**

### 组件传值

#### 父组件传子组件

有时候定义完组件，但是里面的值是并非通过自身的 data 来显示值，而是希望通过导入组件时，传入我们想要的值修改组件的值，这时候就需要通过`props`，将父组件数据传入给子组件，例

:::: tabs type:border-card

::: tab 子组件

```vue
<template>
  <div>
    <div>组件传入的值: {{ val }}</div>
    <div>用户: {{ user.name }}</div>
  </div>
</template>

<script>
export default {
  name: 'Com',
  props: ['val', 'user'],
}
</script>
```

:::

::: tab 父组件

```
<template>
  <div id="app">
	<com :user="user" val="值1"></com>
  </div>
</template>

<script>
import Com from './components/Com.vue'

export default {
  name: 'App',
  data:function(){
    return {
      user: {
        name: "kuizuo"
      },
    };
  },
  components:{
  	Com
  }
}
</script>
```

:::

::::

`props`一般为数组，但也可为对象（但一般没怎么用到），可以指定值的类型，用于验证，例如官方文档的

```js
Vue.component('my-component', {
  props: {
    // 基础的类型检查 (`null` 和 `undefined` 会通过任何类型验证)
    propA: Number,
    // 多个可能的类型
    propB: [String, Number],
    // 必填的字符串
    propC: {
      type: String,
      required: true,
    },
    // 带有默认值的数字
    propD: {
      type: Number,
      default: 100,
    },
    // 带有默认值的对象
    propE: {
      type: Object,
      // 对象或数组默认值必须从一个工厂函数获取
      default: function () {
        return { message: 'hello' }
      },
    },
    // 自定义验证函数
    propF: {
      validator: function (value) {
        // 这个值必须匹配下列字符串中的一个
        return ['success', 'warning', 'danger'].indexOf(value) !== -1
      },
    },
  },
})
```

注：组件传值，如果传入的是字符串都不加`:`，也就是`<Com val="值1"></Com>`的 val 前不用`:`，但如果传入的是其他类型，数值，布尔或变量，对象这些，则需要添加`：`。其实加了冒号就相当于引号内的为 js 表达式一样，比如传入数值 123，就写成`:val="123"`，这里的 123 就是 js 的数值类型。

#### 子组件传父组件

或者说是父组件监听子组件的事件，通过**自定义事件**，触发`$emit`，父组件绑定\$emit，相关代码如下

:::: tabs type:card

::: tab 子组件

```vue
<template>
  <div>
    <button @click="myFn">点击修改父组件内容</button>
  </div>
</template>

<script>
export default {
  methods: {
    myFn: function () {
      // 触发了自定义的changeParent事件，第二个参数 事件参数或事件对象
      this.$emit('changeParent', '愧怍')
    },
  },
}
</script>
```

:::

::: tab 父组件

```vue
<template>
  <div id="app">
    <h1>{{ name }}</h1>
    <childcom @changeParent="changeName"></childcom>
  </div>
</template>

<script>
import Child from './components/Child'
export default {
  name: 'App',
  data: function () {
    return {
      name: 'kuizuo',
    }
  },
  components: {
    Child,
  },
  methods: {
    changeName: function (name) {
      this.name = name //这里的name则就是子组件中$emit函数的第二个参数 "愧怍"
    },
  },
}
</script>
```

:::
::::

也可以这样

```vue
<button v-on:click="$emit("changeParent","愧怍")">点击修改父组件内容</button>
```

自定义事件的流程：

- 在子组件中，通过`$emit()`来触发事件。
- 在父组件中，通过 v-on 来监听子组件事件。

### 父子组件的访问

有时候我们需要父组件直接访问子组件，子组件直接访问父组件，或者是子组件访问根组件。比如

- 父组件访问子组件：使用`$children`或`$refs reference`(引用)。

- 子组件访问父组件：使用`$parent`。

#### $children（少用）

**`this.$children`是一个数组类型，它包含所有子组件对象。**再通过数组下标即可获取的对应的组件对象。

`$children`的缺陷：

通过`$children`访问子组件时，是一个数组类型，访问其中的子组件必须通过索引值。显而易见，当子组件过多，往往不好用索引来确定子组件，如果遍历筛选还更加麻烦，于是就可以用`$refs`

#### $refs（多用）

**`this.$refs`是一个对象类型，它包含所有子组件对象。**

`$refs`的使用：

`$refs`和`ref`指令通常是一起使用的。`$refs`用在父组件中，`ref`用在子组件，如下代码

```vue
<template>
  <div id="app">
    <Com ref="child1" val="子组件1"></Com>
    <Com ref="child2" val="子组件2"></Com>
  </div>
</template>
```

其中 child1 和 child2 相当于 id，父组件可以通过 this.$refs.child1 来访问到

![image-20200921173136538](https://img.kuizuo.cn/image-20200921173136538.png)

通过输出`this`也能找到该两组件。

![image-20200921173756619](https://img.kuizuo.cn/image-20200921173756619.png)

#### **$parent** （少用,不推荐）

子组件中直接访问父组件，可以通过`this.$parent`就行了，尽管在 Vue 开发中，允许通过`$parent`来访问父组件，但是实际开发中尽量不要这样做。

子组件有可能复用，然后复用的父组件极有没有对应的属性，往往就会出现问题。另外，从名字来看，子组件就不应该修改或者访问父组件的状态，而是应该通过父组件传递给子组件，否则很不利于我的调试和维护。

### 组件插槽

有时候整个页面大致框架写好了，这个页面我要不断的使用，例如文章界面和新闻页面我都用这个，但是页面的导航都可能不一样，也就是每个页面又不确定是哪个组件，这时候就可以就可以用到插槽。

通过插槽`slot`可以在组件中，在添加其他的组件或者标签。例如

:::: tabs type:card

::: tab 子组件

```vue
<template>
  <div>
    <div>这是头部</div>
    <div>
      <h1>这是左边</h1>
      <slot name="left"></slot>
    </div>
    <div>
      <h1>这是右边</h1>
      <slot name="right"></slot>
    </div>
    <div>尾部</div>
  </div>
</template>
```

:::

::: tab 父组件

```vue
<template>
  <div id="app">
    <layout>
      <template v-slot:left>
        <div class="left">左边</div>
      </template>
      <template v-slot:right>
        <div class="right">右边</div>
      </template>
    </layout>
  </div>
</template>

<script>
import layout from './components/layout'
export default {
  name: 'App',
  components: {
    layout,
  },
}
</script>
```

:::

::::

在子组件通过`<slot name="插槽名"></slot>` 可以定义插槽的名字，接着在父组件中，要以模板的元素标签`<template v-slot:插槽名></template>`来指定插槽名（这里的插槽名不需要引号）

其中`v-slot:` 可缩写为 `#` 同时**`v-slot` 只能添加在 `<template>` 上** (有[一种例外情况](https://cn.vuejs.org/v2/guide/components-slots.html#独占默认插槽的缩写语法))

### 作用域插槽

有时候数据在子组件中，而展示方式是由我们父组件来决定的，先上代码

:::: tabs type:card

::: tab 子组件

```vue
<template>
  <div>
    <slot :data="arr"></slot>
  </div>
</template>

<script>
export default {
  name: 'Com',
  data() {
    return { arr: ['数组1', '数组2', '数组3'] }
  },
}
</script>
```

:::

::: tab 父组件

```vue
// 父组件
<template>
  <div id="app">
    <Com>
      <template slot-scope="myslot">
        <h1>{{ myslot.data.join('-') }}</h1>
      </template>
    </Com>
    <Com>
      <template slot-scope="myslot">
        <h1>{{ myslot.data.join('+') }}</h1>
      </template>
    </Com>
  </div>
</template>

<script>
import Com from '@/components/Com.vue'

export default {
  name: 'App',
  data: function () {
    return {}
  },
  components: {
    Com,
  },
}
</script>
```

:::

::: tab 展示结果

![image-20200921180943400](https://img.kuizuo.cn/20200921190351.png)

:::

::::

在子组件中，插槽 slot 的数据名为 data，所对的父组件也应为 data（data 是自己取的名字），父组件中通过`slot-scope="myslot"`（myslot 也是自己取的名字），接着`myslot.data`即可获取的子组件的内容，并进行处理

记住一句话：**父组件替换插槽的标签，但是内容由子组件来提供**

### Vue 生命周期

[生命周期](https://cn.vuejs.org/v2/guide/instance.html#%E7%94%9F%E5%91%BD%E5%91%A8%E6%9C%9F%E5%9B%BE%E7%A4%BA)

与之对应的 Vue 代码

```js
<script>
    var app = new Vue({
        el: '#app',
        // 完成创建之前 不能使用data和methods中的数据
        beforeCreate() {
            console.log('before');
        },
        // 数据已经初始化
        created() {
            console.log('created');
        },
        // 模板已将编辑在内存但是并未渲染，数据还未渲染到页面中
        beforeMount() {

        },
         //vue实例 已经挂载好页面了 渲染完毕
        mounted() {

        },
         // 更新页面数据后 内存中data的数据已经改变 但是页面中的数据还没有完成渲染
        beforeUpdate() {

        },
        // 更新数据后 页面和data数据已经同步了
        updated() {

        },
         // 销毁当前实例
        destroyed() {

        },
    })
</script>
```
