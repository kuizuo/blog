---
slug: react-native-develop-experience
title: React Native 开发心得分享
date: 2024-05-14
authors: kuizuo
tags: [react native, 原生, 心得分享]
keywords: [react native, 原生, 心得分享]
image: https://img.kuizuo.cn/2024/0514121158-react-native.png
---

最近研究了一下 React Native(简称RN)，并用它作为毕设项目（一个仿小红书的校园社交应用）。经过一段时间的折腾，对 RN 生态有了一些了解，是时候可以分享一些心得了。

<!-- truncate -->

代码仓库： https://github.com/kuizuo/youni

## 为什么是 RN 而不是 Flutter？

很简单，就是技术栈问题。从开发角度而言，尤其还是对于前端开发人员，会 JS 且搞过 React ，那 RN 上手就十分友好，最起码有关 React 社区的逻辑库或状态库是可以使用的。

虽说 Flutter 的性能是会比 RN 好上不少，但抛开需求不谈，与其比性能不如比开发速度。很显然开发 RN 的效率比 开发 Flutter 高上不少。况且真在意性能的话，那多半就不会考虑跨平台技术了，而是直接考虑原生开发了。

再从需求考量，我所编写的应用更偏向于内容展示的 app，而不是编写一个手机电池监控或者内存监控的app，如果是后者，那这时选择任何跨平台开发都没有意义，像这些系统级别的API在跨平台开发基本不太可能实现的。

对于这两个跨平台技术的选择，应该考虑自身需求、开发成本、技术选型，没有最好的只有最适合的。如果有的选择，谁不会选择原生开发是吧。

但凭我自己接触 RN 以来，国内的 RN 资源甚少，反倒是 Flutter 资源很多，并且从这些相关资料来看，确实 Flutter 优于 RN，但还是那句话，这里就不再过多赘述了。

## 是否有必要学 react-native？

先说一个结论：**RN ≠ 原生，别指望会个 react 就能写出靠谱的原生应用。**

就从我的开发经历来说，坑是真的多，但好在RN拥有庞大的线上社区，可以找到的几乎所有问题的答案。但国内的社区好像并不是很好，很多问题我都是在国外论坛中解决的。

如果你学习它是为了扩展其他平台的开发能力，那么还是可以学习一番的，会有另一番的收获。但如果学 RN 只是为了避免不用学 android 和 iOS 等原生技术就能写 app，那便不建议学习。抱着这心态的话前期开发可能不明显，但到了后面会踩很多坑，而且两眼一黑，因为你不懂 native 开发。

我的个人评价是 RN 只能作为 H5 手机页面运行在原生移动设备的一种展示形态。虽然本质不是，但其所展示的效果如同。RN 不仅仅只是 Web，但也止步于 Web。

顺带吐槽一番，React-Native 项目发布4年多了，还没有 1.0 版本么(¬_¬)

如果你想再继续了解 RN，那么就请往下看。

## Expo

Expo 是基于 React Native 并整合大量常用的 native module([Expo SDK](https://docs.expo.dev/versions/latest/))，像原生的功能如相册，相机，蓝牙等功能，在 expo 都是直接集成的，相当于封装原生的api，暴露给js调用。因此你不用去了解原生开发的许多知识和坑点，上手即用便可。本地配置好应用所需的环境，就直接直接运行 RN 项目，开发十分方便。

此外 Expo 还提供了 [Expo Go App](https://docs.expo.dev/get-started/expo-go/#want-to-understand-how-expo-go-works)，只需要在你的移动端设备中安装它，启动开发服务器并生成 QR 码。在浏览器打开 [snack.expo.dev](https://snack.expo.dev/) ，点击 MyDevice，扫码并在 Expo app 中查看。

![Untitled](https://img.kuizuo.cn/2024/0514104918-Untitled.png)

会自动将该程序实时运行在你的移动端设备，意味着你更改代码也将会同步到Expo go 中。极大程度上提升 RN 的开发体验，尤其是在真机测试阶段。

Expo 官方还贴心的提供了云服务 [Expo Application Services](https://docs.expo.dev/eas/) (EAS)，意为这你可以你可以将你的 RN 项目在托管在云服务上，来执行构建与发布等流程。

总之如今开发 RN 请毫不犹豫的使用上 Expo。

## 开发中遇到的一些坑点

实际开发中所遇到的坑点远不止下述所说，这里只列举几个相对有代表，坑比较深的点。甚至有很多坑都不是前端方面的知识了。

## 在 pnpm 下无法启动 Android

错误提示：Error: Unable to resolve module ./nxode_modules/expo/AppEntry

解决方案：在项目根目录创建 `.npmrc` ，内容如下

```tsx
shamefully-hoist=true
node-linker=hoisted
```

删除 node_modules 与 .expo 文件夹，重新安装依赖即可。

相关链接：[https://github.com/expo/expo/issues/9591#issuecomment-1485871356](https://github.com/expo/expo/issues/9591#issuecomment-1485871356)

### 样式问题

在样式方面与传统的 Web 开发存在一定的区别。在 RN 中有两个主要组件，View 与 Text，可以理解为 Web 的 div 与 span。基本所有的 View 都是 flex 布局，想要让 View 组件占满通常不会使用 width: ’100%’ 或 height: ‘100%’，而是使用 flex: 1，例如一般都会带上这么一个样式。

```tsx
<View style={{ felx: 1 }}>
```

如果样式问题就只是这样就好了，同一套样式在不同平台上所展示的效果都可能不大一样，尤其使用原生 Web 的样式，哪怕你用 style 编写，在 Web 网页也能成功显示效果，但是在 IOS 与 Android 中绝大多数情况下是不显示的。这会在后面介绍 Tailwindcss 相关库的时候会额外在提到一点。

## 文本必须要用 Text 包裹

如果不怎么做的话，会报错，如果只是这样倒还没什么。重点是错误提示并没有堆栈信息！就如下图所示

![Untitled](https://img.kuizuo.cn/2024/0514104918-Untitled%201.png)

这点对于开发体验而言并不友好。

### 模拟器无法请求本地 api

由于一开始是在 Web 端进行调试开发的，所以没留意到这个问题，直到切换到安卓模拟器之后发现模拟器无法请求本地后端服务，在IOS 端暂无这问题。因此需要做如下配置：

1、首先将模拟器内网切换到本地。

假设后端 api 地址为 `[http://localhost:6001](http://localhost:6001)`，正常情况下，开发环境下的调试主机可以通过如下方式获取

```tsx
import Constants from 'expo-constants'

const debuggerHost = Constants.expoConfig?.hostUri
// 192.168.123.233:8081
```

接着所要做的就是将 192.168.123.233:8081 替换成我们的目标端口 192.168.123.233:6001

这里以 axios 为例， 先为环境变量添加 `EXPO_PUBLIC_API_URL=http://localhost:6001`，具体替换的代码如下所示

```tsx
export const client = axios.create({
  baseURL: getApiUrl(),
  timeout: 5000,
})

export function getApiUrl() {
  const apiUrl = process.env.EXPO_PUBLIC_API_URL
  return replaceLocalhost(apiUrl)
}

export function getLocalhost() {
  if (localhost !== undefined) return localhost

  const debuggerHost = Constants.expoConfig?.hostUri
  // 192.168.123.233:8081
  localhost = debuggerHost?.split(':')[0] ?? 'localhost'
  return localhost
}

export function replaceLocalhost(address: string) {
  const PROTOCOL = 'http:'
  const localhostRegex = new RegExp(`${PROTOCOL}\/\/localhost:`, 'g')
  return address.replace(localhostRegex, () => `${PROTOCOL}//${getLocalhost()}:`)
}
```

2、端口转发

此外还需要执行以下命令转发端口。

```tsx
adb reverse tcp:6001 tcp:6001
```

此时安卓模拟器便可正常请求本地后端服务的资源，IOS 端并未有该问题。

## 组件库的选择

如今在 UI 的选择上，我是毫不犹豫选择 Tailwindcss，在 RN 使用 Tailwindcss 有两个库可以作为选择 [nativewind](https://github.com/marklawlor/nativewind) 和 [twrnc](https://github.com/jaredh159/tailwind-react-native-classnames?tab=readme-ov-file)。

### nativewind

nativewind 采用 Web 的 className 属性，其用法如同 Web 开发使用 Tailwindcss 的写法，这里便不过多展示了。

### twrnc

twrnc 的写法则有些不同，需要通过 tw 包装，然后填写到 style 中，就如下图所示

```tsx
import { View, Text } from 'react-native'
import tw from 'twrnc'

const MyComponent = () => (
  <View style={tw`p-4 android:pt-2 bg-white dark:bg-black`}>
    <Text style={tw`text-md text-black dark:text-white`}>Hello World</Text>
  </View>
)
```

:::danger 重点

但要值得注意的是，由于 RN 的组件样式中并不是完全兼容 Web 端，就比如说你想实现毛玻璃效果，通过 [backdrop-blur](https://tailwindcss.com/docs/backdrop-blur) 原子类就可以轻松实现，但是在原生移动端并不能生效，其原因就是原生组件的 View 并没有毛玻璃效果，想要实现则需要使用 expo-blur 这个库。

:::

**事实上有很多 Web 端支持的类，在移动端并不能生效，通常来说只适合用 Tailwindcss 来编写基本的宽高，内外边距等样式。**

#### 这两个库的区别

从 Web 开发使用的角度，nativewind 会更好用一些， npm 实际使用量也确实比 twrnc 来的多，但要在一些情况下，比如给[第三方组件更改 props 的样式](https://www.nativewind.dev/v4/guides/third-party-components)情况下就会没有 twrnc 那么直观了，例如一些第三方组件有 xxxStyle 属性，例如 contentContainerStyle，这时 twrnc 就方便很多。

```tsx
<FlatList style={tw`flex-1`} contentContainerStyle={tw`p-4`} />
```

而 nativewind 则繁琐许多，下图例子。

```tsx
// This component has two 'style' props
function ThirdPartyComponent({ style, contentContainerStyle, ...props }) {
  return <FlatList style={style} contentContainerStyle={contentContainerStyle} {...props} />
}

// Call this once at the entry point of your app
remapProps(ThirdPartyComponent, {
  className: 'style',
  contentContainerClassName: 'contentContainerStyle',
})

// Now you can use the component with NativeWind
<ThirdPartyComponent className="p-5" contentContainerClassName="p-2" />
```

再者，twrnc 可以使用动态变量，例如在 RN 中经常需要处理安全区域，如下写法在 twrnc 就支持，但 nativewind 则不生效。

```tsx
const { top } = useSafeAreaInsets();

<View style={tw`pt-[${top}]`}> // twrnc 支持

<View className={`pt-[${top}]`}> // nativewind 不支持
```

### tamagui(不推荐)

我便提一下 tamagui 这个组件库。tamagui 看似很炫酷，但是实际配置的过程异常的繁琐，用起来也没有特别舒服，可以看以下示例代码。

```tsx
<XStack flex={1} justifyContent="center" alignItems="center" gap="$2">
  <Button size="$3" theme="active">
    Active
  </Button>
  <Button size="$3" variant="outlined">
    Outlined
  </Button>
</XStack>
```

其效果就是一个容器内包含两个按钮，样式编写上则通过 prop 属性来实现，用过 unocss 的 [Attributify Mode](https://unocss.dev/presets/attributify#attributify-mode) 应该会有些许熟悉，但还不那么一样。

并且他的主题系统使用极其的怪，采用 $number 的形式来定义尺寸(官方称 token)，重点是宽高和边距采用相同的 token 效果还不一样，贴个图。

![Untitled](https://img.kuizuo.cn/2024/0514104918-Untitled%202.png)

但他的颜色更是一言难尽了，从 color0 到 color11 的效果就如下图

![Untitled](https://img.kuizuo.cn/2024/0514104918-Untitled%203.png)

可能是因为我用惯了 Tailwindcss 那套颜色系统，所以很不能理解这套颜色系统，并且在我实际编写组件的过程也是异常的奇怪。

但最让我想吐槽的是官方还为此提供了一个主题系统配置的生成器网站，但只有 tamagui 的赞助者才能够使用，如果想要自己定义一个主题，就需要配置特别多的文件，总之就是很难用就对了。

顺带在贴一张 Provider 嵌套

![provider](https://img.kuizuo.cn/2024/0514171536-0514092451-202405140924689.png)

这里我就不得不提到我为啥一开始选用 tamagui 了(现已迁移到 gluestack-ui)，说实话我是有点后悔的，在一开始选定 UI 库的时候，我是选择 NativeWind 的，但后面无意刷到了 [T4-stack](https://t4stack.com/) (算是被他坑了)，而它所用的便是 tamagui，并且一套代码跑 expo 与 next.js。于是便采用相同的项目结构以及 UI 库了。但事实上在我编写的过程中，想要一套代码就能实现跨三端(web,android,ios) 效果并不佳了，这在下一章便会说到。

## gluestack-ui

首先它与 tamagui 相似，也采用 token 的方式来定义尺寸样式，但该库所对标的 token 设计就是Tailwindcss。此外该 UI 提供 NativeWind 的定制方案，意味着你的项目中可以集成了 NativeWind 用 Tailwindcss 的方式编写组件(类似 shadcn/ui)，**并且还在 X 上表示 gluestack-ui + NativeWind 组合就是 React Native 的 shadcn/ui**。

因此我个人是比较看好的，不过目前该库目前还处于 Alpha 阶段，可以持续观望中。这个也是我目前最值得推荐的组件库。

## React Native 和 Next.js 应用程序共享代码

如果你想要在 React Native 和 Next.js 应用程序共享代码(UI，逻辑)，你可以考虑使用 [solito](https://solito.dev/)。该库的写法上会更偏向于 next 的写法，举个例子。

比如说 Image 组件在 RN 写法如下

```tsx
import { Image } from 'react-native'

<Image
  style={styles.xxx}
  source={{
    uri: 'https://beatgig.com/image.png',
  }}
/>
```

next.js 的写法

```tsx
import Image from 'next/image'

<Image src="https://beatgig.com/image.png" width={100} height={100} />
```

solito 的写法

```tsx
import { SolitoImage } from 'solito/image'

<SolitoImage src="https://beatgig.com/image.png" height={100} width={100} />
```

这样 `SolitoImage` 会判断当前的仓库是 next.js 项目还是 RN 项目对不同的平台进行渲染，以做到同一个组件跨平台的开发，像 Link、useRouter 都是类似用法。

不过当你想要共享代码时，此时就必须得上 monorepo 了，通常目录结构如下图所示，你也可以到[这个仓库](https://github.com/gluestack/solito-head-starter-kit)中查看。

```shell
├── apps
│   ├── expo
│   └── next
├── packages
│   └── app
│       ├── features
│       ├── index.ts
│       ├── layouts
│       ├── package.json
│       ├── provider
│       └── screens
├── turbo.json
└── package.json
```

packages/app 存放主要的公共业务代码，在 next 和 expo 中则直接通过 `@xxx/app` 子包来导入，具体可看代码，这里就不做过多介绍了。

### 处理平台差异

不同平台之间必然会存在一定的开发差异，expo 也提供了相应的解决方案，可以通过给文件添加不同的后缀扩展(.web .android .ios) 以在对应平台执行对应文件，官方文档 [Platform specific extensions](https://docs.expo.dev/router/advanced/platform-specific-modules/#platform-specific-extensions)

## 一些库分享

这里只会介绍这个库的用途，至于为什么选择这个而不是其他的，不想做过多的篇幅来解释。如果你用过比这更好的库，也可相互交流。

### [@gorhom/bottom-sheet](https://github.com/gorhom/react-native-bottom-sheet)

底部窗口，效果如图

![https://raw.githubusercontent.com/gorhom/react-native-bottom-sheet/HEAD/preview.gif](https://raw.githubusercontent.com/gorhom/react-native-bottom-sheet/HEAD/preview.gif)

### [@shopify/flash-list](https://github.com/Shopify/flash-list)

一个高性能的列表，可替代 RN 的 [FlatList](https://reactnative.dev/docs/flatlist)，其中它还支持如下图布局。

![Untitled](https://img.kuizuo.cn/2024/0514104918-Untitled%204.png)

[react-native-toast-message](https://github.com/calintamas/react-native-toast-message)

toast 消息组件，轻量简单易用。

![https://github.com/calintamas/react-native-toast-message/raw/main/docs/toast.gif](https://github.com/calintamas/react-native-toast-message/raw/main/docs/toast.gif)

[react-native-gesture-handler](https://github.com/software-mansion/react-native-gesture-handler)

如果你觉得所编写的 RN 应用没有触摸反馈效果，那么可能需要尝试使用 这个库。例如，你可以使用 [RectButton](https://docs.swmansion.com/react-native-gesture-handler/docs/components/buttons/#rectbutton) 来包装子元素来实现点击按钮波纹反馈效果。如下图所示

![https://docs.swmansion.com/react-native-gesture-handler/gifs/samplebutton.gif](https://docs.swmansion.com/react-native-gesture-handler/gifs/samplebutton.gif)

此外像拖动组件、滑动删除、放大缩小图片等常见的手势操作，总之这个库都可以实现。

[react-native-reanimated](https://github.com/software-mansion/react-native-reanimated)

RN 动画库，没啥好说的。

以上组件库可以说基本必装，能为 RN 应用使用体验提升一个档次。

## 一些案例/组件分析

分享一些我在编写 RN 中的一些案例。该说不说，RN 的生态是真的可以，很多原生的解决办法几乎都有。

## [React Navigation](https://reactnavigation.org/)

在这个库你可以实现几乎所有的原生布局，如底部 tabs，左侧抽屉等，expo 是在此基础上进行包装的。

### 底部 Tabs

![https://docs.expo.dev/static/images/expo-router/tabs.png](https://docs.expo.dev/static/images/expo-router/tabs.png)

Expo [自带案例](https://docs.expo.dev/router/advanced/tabs/)，实现效果也简单，这里不在赘述了。

### 左侧抽屉

[https://reactnavigation.org/assets/navigators/drawer/drawer.mp4](https://reactnavigation.org/assets/navigators/drawer/drawer.mp4)

expo 官方所提供的左侧抽屉是带导航的，也就是说你无法同时使用底部选项和左侧抽屉两个布局效果。因此想要同时使用这两种布局，就要使用 [Drawer Layout](https://reactnavigation.org/docs/drawer-layout)，这里分享我个人的实现过程。

首先，编写 DrawerContainer 组件，代码如下

```tsx
import { Drawer } from 'react-native-drawer-layout'
import { useDrawerOpen } from '@/atoms/drawer'
import CustomDrawerContent from './CustomDrawerContent'

export function DrawerContainer({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useDrawerOpen()

  return (
    <Drawer
      open={open}
      onOpen={() => setOpen(true)}
      onClose={() => setOpen(false)}
      swipeEnabled={false}
      renderDrawerContent={() => <CustomDrawerContent></CustomDrawerContent>}
    >
      {children}
    </Drawer>
  )
}
```

如果想要定制化左侧菜单就必须使用 CustomDrawerContent，这里贴相关代码

```tsx
import { DrawerContentScrollView, DrawerItem } from '@react-navigation/drawer'

export default function CustomDrawerContent() {
  return (
    <DrawerContentScrollView
      scrollEnabled={false}
      contentContainerStyle={{
        flexGrow: 1,
      }}
    >
      {/* <DrawerItemList {...props} /> */}

      <View className="flex-1 mx-2">

        <DrawerItem
          label="子项 1"
          onPress={() => { }}
        />
        <DrawerItem
          label="子项 2"
          onPress={() => { }}
        />
        {/* ... */}
      </VStack>
    </DrawerContentScrollView>
  )
}
```

最后在 app/\_layout.tsx 中用 DrawerContainer 包装一下 Stack，如下代码。

```tsx
import { Stack } from 'expo-router'
import { Provider } from '@/provider'
import { DrawerContainer } from '@/components/DrawerContainer'

export default function RootLayout() {
  return (
    <Provider>
      <DrawerContainer>
        <Stack
          screenOptions={{
            headerShown: false,
          }}
        ></Stack>
      </DrawerContainer>
    </Provider>
  )
}
```

此时就可以用 useDrawerOpen（这里状态库选用 jotai）来控制左侧菜单的展开了。

### TabView

![https://reactnavigation.org/assets/libraries/tab-view.gif](https://reactnavigation.org/assets/libraries/tab-view.gif)

同样的，这个效果在 [React Navigation](https://reactnavigation.org/docs/tab-view) 也是有提供的。但在 expo 中有 react-native-pager-view作为平替，并且更兼容原生，但是 react-native-pager-view 是不支持 Web 端的，因此如何选择就看具体需求了。

### 固定 Header + tab view

先看一张图，很多 app 都有这种类似的效果。

![](https://img.kuizuo.cn/2024/0514171652-Untitled.mp4)

这种效果可以使用监听 ScrollY 配合 [react-native-reanimated](https://github.com/software-mansion/react-native-reanimated) 动画来实现，如果你不想自己实现也可以看看 [@codeherence/react-native-header](https://react-native-header.codeherence.com/docs/showcase)，上图便来自此库。

此外我还留意到 [TabbedHeaderPager](https://netguru.github.io/sticky-parallax-header/docs/introduction/getting-started) 这个库（很坑，别用），别看官方 gif 图效果很炫酷，然而实际效果并不达预期，并且十分难用，比如想要更改 tab 样式得像下方这样传递 props 编写。

```tsx
<TabbedHeaderPager
  tabTextStyle={{
    color: theme.color?.get(),
    padding: 0,
  }}
  tabTextActiveStyle={{
    backgroundColor: 'transparent',
  }}
  tabTextContainerStyle={{
    padding: 0,
  }}
  tabTextContainerActiveStyle={{
    backgroundColor: 'transparent',
  }}
  tabWrapperStyle={{
    paddingVertical: 0,
  }}
  tabUnderlineColor={primaryColor}
  tabsContainerStyle={{
    backgroundColor: bgColor,
    flex: 1,
    maxWidth: Platform.select({
      web: 200,
    }),
    margin: Platform.select({
      web: 'auto',
    }),
  }}
  tabsContainerHorizontalPadding={Platform.select({
    default: 120,
    web: 0,
  })}
  contentContainerStyle={{
    flex: 1,
  }}
/>
```

## RN 原生开发的感悟

在这段的 RN 开发经历，我还有很多 API 还未尝试，有很多开发上的细节没编写到。篇幅有限，未来如果还有机会编写 RN 项目，再做一些分享(我觉得应该不会有了)。

我曾与安卓开发打过两次交道:

一段是在学习安卓逆向的时候，免不了学习一些基础的原生安卓开发的知识。

另一段是在接触自动化开发的时候，看到了 [Auto.js](https://www.wuyunai.com/docs/) 这个库， 可以使用 JavaScript 和 Node.js 实现小型的安卓应用（不支持 IOS），更多是使用这个库来编写一些脚本类相关的应用。现在回看该库的文档，不由得开始莫名的感叹。

> Auto.js Pro 移除了自动化测试、图片处理、消息通知等模块，如果你需要实现的是自动化、工作流工具，则不适合 Auto.js Pro。

在如今内卷的环境下，技术框架变化飞快，文档示例不断完善，服务商们也提供快速搭建应用的模版，又赶上了 AI 热潮，学习一件新东西对于初学者过于容易。随之而来的是开发人员变多，市场需求不足难以满足如此庞大的开发人员，貌似技术对开发人员本身也不是那么的重要？

对于技术人员要如何破局，或许是每位程序员的最值得思考的问题。
