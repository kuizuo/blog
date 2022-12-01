---
slug: vscode-extension
title: 写一个VSCode扩展
date: 2022-07-11
authors: kuizuo
tags: [vscode, plugin, extension, develop]
keywords: [vscode, plugin, extension, develop]
description: 编写一个属于个人定制化的 VSCode 扩展，并将其发布到应用商店中
image: /img/project/vscode-extension.png
sticky: 4
---

自从使用过 VSCode 后就再也离不开 VSCode，其轻量的代码编辑器与诸多插件让多数开发者爱不释手。同样我也不例外，一年前的我甚至还特意买本《Visual Studio Code 权威指南》的书籍，来更进一步了解与使用。

在购买这本书时就想写一个 vscode 插件（扩展），奈何当时事务繁忙加之不知做何功能，就迟迟未能动手。如今有时间了，就顺带体验下 vscode 扩展开发，并记录整个开发过程。

扩展地址：[VSCode-extension](https://marketplace.visualstudio.com/items?itemName=kuizuo.vscode-extension-sample 'VSCode-extension')

开源地址：[kuizuo/vscode-extension (github.com)](https://github.com/kuizuo/vscode-extension)

![vscode-extension](https://img.kuizuo.cn/image-20220711195038039.png)

<!-- truncate -->

## Vscode 相关

[vscode 应用商店](https://marketplace.visualstudio.com/vscode 'vscode应用商店')

[vscode 插件官方文档](https://code.visualstudio.com/api 'vscode插件官方文档')

[vscode 官方插件例子](https://github.com/microsoft/vscode-extension-samples 'vscode 官方插件例子')

关于 Vscode 及其插件就不过多介绍，相信这篇文章 [VSCode 插件开发全攻略（一）概览 - 我是小茗同学 - 博客园](https://www.cnblogs.com/liuxianan/p/vscode-plugin-overview.html 'VSCode插件开发全攻略（一）概览 - 我是小茗同学 - 博客园')能告诉你 Vscode 插件的作用。

## 工具准备

:::tip

**在开发前，建议关闭所有功能性扩展，以防止部分日志输出与调试效率**。

:::

### vscode 插件脚手架

vscode 提供插件开发的脚手架 [vscode-generator-code](https://github.com/Microsoft/vscode-generator-code 'vscode-generator-code') 来生成项目结构，选择要生成的类型

```shell
? ==========================================================================
We're constantly looking for ways to make yo better!
May we anonymously report usage statistics to improve the tool over time?
More info: https://github.com/yeoman/insight & http://yeoman.io
========================================================================== Yes

     _-----_     ╭──────────────────────────╮
    |       |    │   Welcome to the Visual  │
    |--(o)--|    │   Studio Code Extension  │
   `---------´   │        generator!        │
    ( _´U`_ )    ╰──────────────────────────╯
    /___A___\   /
     |  ~  |
   __'.___.'__
 ´   `  |° ´ Y `

? What type of extension do you want to create? (Use arrow keys)
> New Extension (TypeScript)
  New Extension (JavaScript)
  New Color Theme
  New Language Support
  New Code Snippets
  New Keymap
  New Extension Pack
  New Language Pack (Localization)
  New Web Extension (TypeScript)
  New Notebook Renderer (TypeScript)
```

根据指示一步步选择，这里省略勾选过程，最终生成的项目结果如下

![](https://img.kuizuo.cn/image_StiMqQrFCi.png)

### 运行 vscode 插件

既然创建好了工程，那必然是要运行的。由于我这里选择的 ts ＋ webpack 进行开发（视情况勾选webpack），所以是需要打包，同时脚手架已经生成好了对应.vscode 的设置。只需要按下 F5 即可开始调试，这时会打开一个新的 vscode 窗口，`Ctrl+Shift+P`打开命令行，输入`Hello World`，右下角弹出提示框`Hello World from kuizuo-plugin!`

:::danger

注意: 由于是 webpack 开发，在调用堆栈中可以看到有两个进程，一个是 webpack，另一个是新开的插件窗口的，同时在该调试窗口也能查看调试输出信息。

![](https://img.kuizuo.cn/image_Yv4X32qLE5.png)

**切记一定要等到第二个调试进程加载完毕**（时间根据电脑性能而定），再打开命令行输入 Hello World 才会有命令，否则会提示 没有匹配命令。

:::

至此，一个 vscode 的开发环境就已经搭建完毕，接下来就是了解项目结构，以及 vscode 插件的 api 了。

### 代码解读

```typescript title="extension.ts"
import * as vscode from 'vscode'

export function activate(context: vscode.ExtensionContext) {
  let disposable = vscode.commands.registerCommand('kuizuo-plugin.helloWorld', () => {
    vscode.window.showInformationMessage('Hello World from kuizuo-plugin!')
  })

  context.subscriptions.push(disposable)
}

export function deactivate() {}
```

`vscode.commands.registerCommand`用于注册命令，`kuizuo-plugin.helloWorld` 为命令 ID，在后续`package.json`中要与之匹配。第二个参数为一个回调函数，当触发该命令时，弹出提示框。

在 package.json 中关注 activationEvents 与 contributes

```json title="package.json"
{
  "activationEvents": ["onCommand:kuizuo-plugin.helloWorld"],
  "contributes": {
    "commands": [
      {
        "command": "kuizuo-plugin.helloWorld",
        "title": "Hello World"
      }
    ]
  }
}
```

activationEvents 激活事件，`onCommand:kuizuo-plugin.helloWorld`中`kuizuo-plugin`是插件 ID 要与 extension.ts 中的注册命令匹配，`helloWorld`则是命令标识，而 onCommand 则是监听的类型，此外还有`onView`、`onUri`、`onLanguage`等等。

contributes 则是配置那些地方来显示命令，像官方的例子中，就是在 Ctrl + Shift + P 命令行中输入 Hello World 来调用`kuizuo-plugin.helloWorld` 命令。此外还可以设置按键与菜单

```json title="package.json"
"keybindings": [
      {
        "command": "kuizuo-plugin.helloWorld",
        "key": "ctrl+f10",
        "mac": "cmd+f10",
        "when": "editorTextFocus"
      }
    ],
    "menus": {
      "editor/context": [
        {
          "when": "editorFocus",
          "command": "kuizuo-plugin.helloWorld",
          "group": "navigation"
        }
      ]
    }
```

设置完毕后，可以按 Ctrl + Alt + O 或者命令行中键入 reload 来重启 vscode

:::danger

这里也要注意，如果重启后并无生效，请查看 package.json 是否配置正确（多一个逗号都不行），或者尝试重新调试。如果还不行，那么很有可能就是代码报错，但日志输出并没有，那么在弹出的新窗口中打开开发人员工具（Ctrl+Alt+I 或帮助 → 切换开发人员工具），这里有报错相关的提示信息。

建议查看[VSCode 插件开发全攻略（六）开发调试技巧](https://www.cnblogs.com/liuxianan/p/vscode-plugin-develop-tips.html 'VSCode插件开发全攻略（六）开发调试技巧')

:::

## 功能

### 首次启动弹窗与配置项

先说首次启动弹窗的实现，要实现该功能，肯定要保证插件在 VSCode 一打开就运行，而这取决于 vscode 触发插件的时机，也就是 activationEvents，所以`activationEvents`需要设置成`onStartupFinished`。想要更高的优先级，可以选择 `*` （但官方不建议，除非其他事件无法实现的前提下），这里为了演示就使用`*`。

其实现代码主要调用 `vscode.window.showInformationMessage` 函数如下

```typescript title="extension.ts"
import * as vscode from 'vscode'
import { exec } from 'child_process'

export function activate(context: vscode.ExtensionContext) {
  vscode.window.showInformationMessage('是否要打开愧怍的小站？', '是', '否', '不再提示').then((result) => {
    if (result === '是') {
      exec(`start 'https://kuizuo.cn'`)
    } else if (result === '不再提示') {
      // 其他操作 后文会说
    }
  })
}
```

此时重启窗口，就会有如下弹窗显示

![](https://img.kuizuo.cn/image_9oqLzZl-wE.png)

但如果你是 mac 用户的话，你会发现无法打开，其原因是 window 下打开链接的指令是 start，而 mac 则是 open，所以需要区分不同的系统。要区分系统就可以使用 node 中的 os 模块的 platform 方法获取系统，如下（省略部分代码）

```typescript
import * as os from 'os'

const commandLine = os.platform() === 'win32' ? `start https://kuizuo.cn` : `open https://kuizuo.cn`
exec(commandLine)
```

当然了，当用户选择不再提示的时候，下次再打开 vscode 就别提示了，不然大概率就是卸载插件了。这里就需要设置全局参数了，在 package.json 中 contributes 设置 configuration，具体如下，注意`kuizuoPlugin.showTip` 为全局参数之一

```json title="package.json"
"contributes": {
  "configuration": {
    "title": "kuizuo-plugin",
    "properties": {
      "kuizuoPlugin.showTip": {
        "type": "boolean",
        "default": true,
        "description": "是否在每次启动时显示欢迎提示！"
      }
    }
  }
}
```

该参数可以在设置 → 扩展中找到`kuizuo-plugin`插件来手动选择，也可以是通过 api 来修改

![](https://img.kuizuo.cn/image_teNrxe9D9O.png)

然后读取`vscode.workspace.getConfiguration().get(key)`和设置该参数`vscode.workspace.getConfiguration().update(key, value)`

```typescript title="extension.ts"
export async function activate(context: vscode.ExtensionContext) {
  const key = 'kuizuoPlugin.showTip'
  const showTip = vscode.workspace.getConfiguration().get(key)
  if (showTip) {
    const result = await vscode.window.showInformationMessage('是否要打开愧怍的小站？', '是', '否', '不再提示')
    if (result === '是') {
      const commandLine = os.platform() === 'win32' ? `start https://kuizuo.cn` : `open https://kuizuo.cn`
      exec(commandLine)
    } else if (result === '不再提示') {
      //最后一个参数，为true时表示写入全局配置，为false或不传时则只写入工作区配置
      await vscode.workspace.getConfiguration().update(key, false, true)
    }
  }
}
```

即便是调试状态下，重启也不会影响全局参数。最终封装完整代码查看源码，这里不再做展示了。

### 右键资源管理器（快捷键）新建测试文件

我日常开发中写的最多的文件就是 js/ts 了，有时候就会在目录下创建 demo.js 来简单测试编写 js 代码，那么我就要点击资源管理器，然后右键新建文件，输入 demo.js。于是我想的是将该功能**封装成快捷键**的方式，当然右键也有**新建测试文件**这一选项。

![](https://img.kuizuo.cn/image_3SRybBGaF1.png)

功能其实挺鸡肋的，也挺高不了多少效率，这里可以说**为了演示和测试这个功能而实现**。

总之前面这么多废话相当于铺垫了，具体还是看功能实现吧。

首先就是注册命令，具体就不解读代码了，其逻辑就是获取调用`vscode.window.showQuickPick`弹出选择框选择 js 还是 ts 文件（自定义），接着获取到其目录，判断文件是否存在，创建文件等操作。

```typescript title="extension.ts"
import * as vscode from 'vscode'
import * as fs from 'fs'

export async function activate(context: vscode.ExtensionContext) {
  let disposable = vscode.commands.registerCommand('kuizuo-plugin.newFile', (uri: vscode.Uri) => {
    vscode.window.showQuickPick(['js', 'ts'], {}).then(async (item) => {
      if (!uri?.fsPath) {
        return
      }

      const filename = `${uri.fsPath}/demo.${item}`
      if (fs.existsSync(filename)) {
        vscode.window.showErrorMessage(`文件${filename}已存在`)
        return
      }

      fs.writeFile(filename, '', () => {
        vscode.window.showInformationMessage(`demo.${item}已创建`)
        vscode.window.showTextDocument(vscode.Uri.file(filename), {
          viewColumn: vscode.ViewColumn.Two, // 显示在第二个编辑器窗口
        })
      })
    })
  })

  context.subscriptions.push(disposable)
}

export function deactivate() {}
```

然后再 keybindins 中添加一条

```json title="package.json"
"keybindings": [
  {
    "command": "kuizuo-plugin.newFile",
    "key": "shift+alt+n",
  }
],
```

然后就当我实现完功能的时候，我在想**自带的新建文件是不是就是个 command？只是没有绑定快捷键？** 于是我到键盘快捷方式中找到答案

![](https://img.kuizuo.cn/image_nQu3Y8DWSw.png)

图中的`explorer.newFile`就是资源管理器右键新建文件的命令，只是没有键绑定。所以我只需要简单的加上`shift + alt + n`即可实现我一开始想要的快捷键功能，此时再次右键资源管理器新建文件右侧就有对应的快捷键。

此时的我不知该哭该笑，折腾半天的功能其实只是设置个快捷键的事情。

:::note

这些命令在 vscode 中作为内置命令[Built-in Commands](https://code.visualstudio.com/api/references/commands 'Built-in Commands')。要查看 vscode 所有命令的话，也可以通过`vscode.commands.getCommands` 来获取所有命令 ID，要在插件中执行也只需要调用`vscode.commands.executeCommand(id)`&#x20;

:::

### 键盘快捷键（光标移动）

接着我就在想，既然很多 vscode 功能都是命令的形式，那是不是在插件级别就能做键盘映射，而不用让用户在 vscode 设置，很显然是可以的。只需要在 package.json 中 contributes 的 keybindings 中设置，就可以实现组合键来进行光标的移动。下面是我给出的答案

```json title="package.json"
"keybindings": [
      {
        "command": "cursorUp",
        "key": "shift+alt+i",
        "when": "textInputFocus"
      },
      {
        "command": "cursorDown",
        "key": "shift+alt+k",
        "when": "textInputFocus"
      },
      {
        "command": "cursorLeft",
        "key": "shift+alt+j",
        "when": "textInputFocus"
      },
      {
        "command": "cursorRight",
        "key": "shift+alt+l",
        "when": "textInputFocus"
      },
      {
        "command": "cursorHome",
        "key": "shift+alt+h",
        "when": "textInputFocus"
      },
      {
        "command": "cursorEnd",
        "key": "shift+alt+;",
        "when": "textInputFocus"
      }
    ]
```

![](https://img.kuizuo.cn/image_SnnPUABJN5.png)

仔细看右侧来源就可以知道是没问题的，第一个为我之前设置的，而扩展则是通过上面的方法。

### 自定义扩展工作台

在 vscode 中有几个地方可以用于扩展，具体可看[Extending Workbench | Visual Studio Code Extension API](https://code.visualstudio.com/api/extension-capabilities/extending-workbench#status-bar-item 'Extending Workbench | Visual Studio Code Extension API')

![](https://code.visualstudio.com/assets/api/extension-capabilities/extending-workbench/workbench-contribution.png)

- 左侧图标（活动栏）：主要有资源管理器、搜索、调试、源代码管理、插件

- 编辑器右上角：代码分栏、code runner 的运行图标

- 底部（状态栏）：git、消息、编码等等

在 contributes 添加 viewsContainers 与 views，注意，views 的属性要与 viewsContainers 的 id 对应。

```json title="package.json"
"viewsContainers": {
  "activitybar": [
    {
      "id": "demo",
      "title": "愧怍",
      "icon": "public/lollipop.svg"
    }
  ]
},
"views": {
  "demo": [
    {
      "id": "view1",
      "name": "视图1"
    },
    {
      "id": "view2",
      "name": "视图2"
    }
  ]
}
```

编辑器右上角是在 menus 中设置 editor/title，图标则是对应命令下设置，不然就是显示文字

```json title="package.json"
"commands": [
    {
      "command": "kuizuo-plugin.helloWorld",
      "title": "Hello World",
      "icon": {
        "light": "public/lollipop.svg",
        "dark": "public/lollipop.svg"
      }
    }
],
"menus": {
    "editor/title": [
      {
        "when": "resourceLangId == javascript",
        "command": "kuizuo-plugin.helloWorld",
        "group": "navigation"
      }
    ],
}
```

至于底部状态栏，这里借用官方例子[vscode-extension-samples/statusbar-sample at main · microsoft/vscode-extension-samples (github.com)](https://github.com/microsoft/vscode-extension-samples/tree/main/statusbar-sample 'vscode-extension-samples/statusbar-sample at main · microsoft/vscode-extension-samples (github.com)')，最终效果如下

![](https://img.kuizuo.cn/image_yQRsMkT6f5.png)

那个 🍭 就是所添加的图标，不过并不实际功能，这里只是作为展示。

### 自定义颜色、图标主题

在 vscode 中分别有三部分的主题可以设置

| 主题         | 范围                       | 推荐                                                                                                 |
| ------------ | -------------------------- | ---------------------------------------------------------------------------------------------------- |
| 文件图标主题 | 资源管理器内的文件前的图标 | [Material Icon Theme](https://marketplace.visualstudio.com/items?itemName=PKief.material-icon-theme) |
| 颜色主题     | 代码编辑器以及整体颜色主题 | [One Dark Pro](https://marketplace.visualstudio.com/items?itemName=zhuangtongfa.Material-theme)      |
| 产品图标主题 | 左侧的图标                 | [Carbon Product Icons](https://marketplace.visualstudio.com/items?itemName=antfu.icons-carbon)       |

不过关于主题美化就不做深入研究，上面所推荐的就已经足够好看，个人目前也在使用。

### 代码片段

代码片段，也叫`snippets`，相信大家都不陌生，就是输入一个很简单的单词然后一回车带出来很多代码。平时大家也可以直接在 vscode 中创建属于自己的`snippets`

代码片段相对比较简单，这里就简单跳过了

### xxx.log → console.log(xxx)包装

功能描述：在一个变量后使用.log，即可转化为 console.log(变量)的形式就像 `xxx.log => console.log('xxx', xxx)` 有点像 idea 中的`.sout`

这里我把 [jaluik/dot-log](https://github.com/jaluik/dot-log) 这个插件的实现逻辑给简化了，这里先给出基本雏形

```typescript title="extension.ts"
import * as vscode from 'vscode'

class MyCompletionItemProvider implements vscode.CompletionItemProvider {
  constructor() {}

  // 提供代码提示的候选项
  public provideCompletionItems(document: vscode.TextDocument, position: vscode.Position) {
    const snippetCompletion = new vscode.CompletionItem('log', vscode.CompletionItemKind.Operator)
    snippetCompletion.documentation = new vscode.MarkdownString('quick console.log result')

    return [snippetCompletion]
  }

  // 光标选中当前自动补全item时触发动作
  public resolveCompletionItem(item: vscode.CompletionItem) {
    return null
  }
}

export function activate(context: vscode.ExtensionContext) {
  const disposable = vscode.languages.registerCompletionItemProvider(
    ['html', 'javascript', 'javascriptreact', 'typescript', 'typescriptreact', 'vue'],
    new MyCompletionItemProvider(),
    '.', // 注册代码建议提示，只有当按下“.”时才触发
  )

  context.subscriptions.push(disposable)
}
```

在 vscode 插件中通过`vscode.languages.registerCompletionItemProvider`提供像补全，代码提示等功能，第一个参数为所支持的语言，第二个参数为提供的服务`vscode.CompletionItemProvider`
这里只是封装成类的形式，目的是为了保存一些属性，例如光标位置 position，也可以传递对象形式
`{ provideCompletionItems, resolveCompletionItem }` ，第三个参数则是触发的时机。

`provideCompletionItems`
需返回一个数组，成员类型为`vscode.CompletionItem`，可通过`new vscode.CompletionItem()`来创建。

当你尝试运行上述代码时，会发现在任何值后面输入`.`都会有`log`提示。

![](https://img.kuizuo.cn/image_-ZCy88xVyq.png)

但是点击后只是满足了代码补全的功能，而选择 log 选项后所要执行的操作则是在 `resolveCompletionItem` 中实现，这里仅仅只是返回一个
null，即只有简单的补全功能，这里对整个过程进行描述（可以自行下个断点调试查看）：。

1. 当输入`.`时，程序进入到`provideCompletionItems`
   函数内，这里可以获取到当前正在编辑的代码文档（文件名，代码内容）对应第一个参数，以及光标所在位置也就是第二个参数。还有其他参数，但这里用不到。具体可看[CompletionItemProvider](https://code.visualstudio.com/api/references/vscode-api#CompletionItemProvider%3CT%3E 'CompletionItemProvider')

2. 选择完毕后，便会进入到 resolveCompletionItem 里面，这里可以获取到用户所选的选项内容，然后执行一系列的操作。

要做代码替换的话就需要注册文本编辑命令`vscode.commands.registerTextEditorCommand` ，内容如下

```typescript title="extension.ts"
const commandId = 'kuizuo-plugin.log'
const commandHandler = (editor: vscode.TextEditor, edit: vscode.TextEditorEdit, position: vscode.Position) => {
  const lineText = editor.document.lineAt(position.line).text
  // match case name.log etc.
  const matchVarReg = new RegExp(`\(\[^\\s\]*\[^\'\"\`\]\).${'log'}$`)
  // match case 'name'.log etc.  /(['"`])([^'"])\1.log/
  const matchStrReg = new RegExp(`\(\[\'\"\`\]\)\(\[^\'\"\`\]*\)\\1\.${'log'}$`)
  let matchFlag: 'var' | 'str' = 'var'
  let text,
    key,
    quote = "'",
    insertVal = ''
  ;[text, key] = lineText.match(matchVarReg) || []
  if (!key) {
    ;[text, quote, key] = lineText.match(matchStrReg) || []
    matchFlag = 'str'
  }
  // if matched
  if (key) {
    const index = lineText.indexOf(text)
    edit.delete(new vscode.Range(position.with(undefined, index), position.with(undefined, index + text.length)))

    if (matchFlag === 'var' && key.includes("'")) {
      quote = '"'
    }
    // format like console.log("xxx", xxx)
    if (matchFlag === 'var') {
      //  only console.log(xxx)
      insertVal = `${'console.log'}(${key})`
    }
    // if key is string format like console.log("xxx")
    if (matchFlag === 'str') {
      insertVal = `${'console.log'}(${quote}${key}${quote})`
    }

    edit.insert(position.with(undefined, index), insertVal)
  }

  return Promise.resolve([])
}
context.subscriptions.push(vscode.commands.registerTextEditorCommand(commandId, commandHandler))
```

`registerTextEditorCommand`不同于`registerCommand`，它只针对编辑器的命令，例如可以删除代码中的某个片段，增加代码等等。上面的代码就是为了找到.log
前（包括.log）匹配的代码，进行正则提取，然后调用 edit.delete 删除指定范围，再调用 edit.insert
来插入要替换的代码，以此达到替换的效果。

命令注册完毕了就需要调用了，也就到了 resolveCompletionItem 的时机

```typescript title="extension.ts"
  public resolveCompletionItem(item: vscode.CompletionItem) {
    const label = item.label
    if (this.position && typeof label === 'string') {
      item.command = {
        command: 'kuizuo-plugin.log',
        title: 'refactor',
        arguments: [this.position.translate(0, label.length + 1)], // 这里可以传递参数给该命令
      }
    }

    return item
  }
```

将命令赋值给 item.command，会自动调用其 command 命令，同时把 arguments 参数传入给 command。最终达到替换的效果。

#### Position

这里要说下 vscode 编辑器中的 Position，了解这个对代码替换、代码定位、代码高亮有很大帮助。

position 有两个属性`line`和`character`，对应的也就是行号和列号（后文以`line`和`character`
为称），**\*\***和\***\*都是从 0 开始算起，而在 vscode 自带的状态栏提示中则是从 1 开始算起**，这两者可别混淆了。

其中 position 有如下几个方法

**position.translate**

根据当前坐标计算，例如当前 position 的 line 0，character1。`position.translate(1, 1)` 得到 line
1，character 2，这不会改变远 position，这很好理解。但如果计算后得到的 line 与 character 有一个为负数则直接报错。

**position.with**

从自身创建一个新的 postion 对象

#### Range

知道了坐标信息，那么就可以获取范围了。可以通过 new vscode.Range() 来截取两个 position 之间的内容，得到的是一个 对象，有
start 与 end 属性，分别是传入的两个 position。

同样的 Range 和 Postion 方法都一致，这里就不多叙述了，可查看其声明文件。
知道范围就可以通过 editor 来获取范围内的代码或是 edit 来删除代码等操作。

知道了这些内容，再看上面的代码也不难理解了。

### 选中变量并打印 console.log

这里在补充一个功能：选中一个变量的时候，按下快捷键在下方添加`console.log(变量)`，相关插件 [Turbo Console Log](https://marketplace.visualstudio.com/items?itemName=ChakrounAnas.turbo-console-log 'Turbo Console Log')

补：只有编辑器有光标的情况下会传入当前光标属性 position，选中状态下是不会传入 postion
属性，而是要通过`editor.selection`来获取选中内容，是一个 Selection 对象。

```typescript title="extension.ts"
context.subscriptions.push(
  vscode.commands.registerTextEditorCommand(
    'kuizuo-plugin.insertLog',
    (editor: vscode.TextEditor, edit: vscode.TextEditorEdit) => {
      // 获取选中代码 在其下方插入 console.log(xxx)
      const { selection, selections } = editor
      // 选中多个代码时
      if (selections.length > 1) {
        return
      }

      // 如果不是当行代码
      if (!selection.isSingleLine) {
        return
      }

      const value = editor.document.getText(selection)
      const insertVal = `${os.EOL}${'console.log'}('${value}', ${value})`

      edit.insert(editor.selection.end, insertVal)
      editor.selection = new vscode.Selection(editor.selection.end, editor.selection.end) // 重置选中区域
      return Promise.resolve([])
    },
  ),
)
```

### 悬停提示

这里也一笔带过，具体可看 hover.ts 中的代码。只要在 json 文件中，将鼠标悬停在`kuizuo`这个词中即可触发，试试看看。

![](https://img.kuizuo.cn/image_RUIjdDI90l.png)

### WebView

使用 webView 可以在 vscode 内显示自定义的网页内容，丰富 vscode 功能，但所消耗的性能是肯定有的，就有可能影响 vscode
的运行速度。官方给出的建议是：

- 这个功能真的需要放在`VSCode`中吗？作为单独的应用程序或网站会不会更好呢？

- webview 是实现这个功能的唯一方法吗？可以使用常规 VS Code API 吗？

- 您的 webview 是否会带来足够的用户价值以证明其高资源成本？

不过这里还只是作为一个演示，点击右上角的 logo 图标便可在 vscode 中打开网页。

![](https://img.kuizuo.cn/image_nVO_YmRit4.png)

不过要注意一点。新开的 webview 的背景是对应主题颜色的背景，如果网站有黑白模式的话，那么可能会导致颜色不对，故这里设置了 webview 的背景为白色。

至于消息通信就不尝试了。

## 发布

大部分常用的 vscode 插件实现就此完毕，实际上有很多 api 还没尝试过，篇幅有限，就不一一列举了，后续若有开发实际作用插件再研究。具体可自行安装尝试一番，既然要让别人安装，这里就需要介绍发布了。

这里在打包前重构下命令 ID，从 kuizuo-plugin → vscode-extension，同时把 package.json 的 name 改成了 vscode-extension-sample，因为发布的时候这个 id 必须唯一，不能与已有重名，到时候生成的为 kuizuo.vscode-extension-sample。（demo 给取了，不然我也不想起名为 sample）

### 本地打包

无论是本地打包还是发布到应用市场都需要借助`vsce`这个工具。

安装

```bash
npm i vsce -g
```

打包成`vsix`文件：

```bash
vsce package
```

:::danger

如果使用pnpm的话，有可能会打包失败，提示：npm ERR! missing: xxxxxx

:::

在打包时会提示一些信息，例如修改 README.md ，添加 LICENSE 等等，根据提示来操作即可。

生成好的 vsix 文件不能直接拖入安装，只能从扩展的右上角选择`Install from VSIX`安装：

### 发布到应用市场

**1、注册账号获取 token**

因为 Visual Studio Code 使用 [Azure DevOps](https://azure.microsoft.com/services/devops/)作为其 Marketplace 服务。所以需要登录一下[Azure](https://dev.azure.com/ 'Azure')。登录后，如果之前没用过的话会要求创建一个组织，默认为邮箱前缀，这里如下点击

![](https://img.kuizuo.cn/token1_JNXknLPQyJ.png)

**2、新建一个 token**

![image-20220831152146541](https://img.kuizuo.cn/image-20220831152146541.png)

根据图片选择，注意其中 `Organization` 选择 `All aaccessible organizations`，`Scopes` 选择：`Full access`，否则登录会失败。生成后会得到一个 token，保存它，当你关闭时便不再显示。

**3、创建一个发布者**

先使用网页版创建发布账号：[https://marketplace.visualstudio.com/manage](https://marketplace.visualstudio.com/manage 'https://marketplace.visualstudio.com/manage')填写一些基本信息，然后在使用

```bash
vsce login <publisher name>
```

这里的 `publisher name` 根据 package.json 中的 `publisher`，会要求你输入 `Personal Access Token`，把刚刚创建的 `token` 的值粘贴过来即可

提示
`The Personal Access Token verification succeeded for the publisher 'kuizuo'.`
就说明验证成功

**4、发布应用**

```bash
vsce publish
```

:::warning
这里要保证 package.json 的 name 在插件市场中唯一，否则会提示 The Extension Id already exist in the Marketplace. Please use the different Id。
:::

运行完毕后，最终提示`Published kuizuo.vscode-extension-sample v1.0.0.` 就说明发布完毕，发布和 npm 包一样，都无需审核，但要求包名唯一。

可以在 [Manage Extensions | Visual Studio Marketplace](https://marketplace.visualstudio.com/manage/publishers/kuizuo 'Manage Extensions | Visual Studio Marketplace') 中管理已发布的插件

![](https://img.kuizuo.cn/image_HssaMdar8f.png)

这时在 vscode 扩展商店中搜索 `vscode-extension-sample`就能找到该插件[VSCode-extension](https://marketplace.visualstudio.com/items?itemName=kuizuo.vscode-extension-sample 'VSCode-extension')，也可以通过`publisher:"kuizuo"`来找到我的所有 vscode 插件。

![vscode-extension](https://img.kuizuo.cn/image-20220711195038039.png)

## 总结

整个开发过程的体验还是非常不错的，调试和代码提示都做得特别到位。不过有一点体验不好的，是大部分的配置信息都要写在 package.json 中，而在这里就不像 ts 那样有没有很好的代码提示了。不过当你填错命令 id 的时，vscode 还会提示命令 id 不存在，而不是不知道报错点。

浅浅吐槽下：说真的 vscode 插件开发相关的文章与教程少之又少，有时候一个功能的一个 api 实现只能去查阅文档，而不像 chrome 插件，通过搜索引擎就能很快得出结果，而 vscode 插件往往得到的是推荐...但这也说明 chrome 插件开发的人远多于 vscode 插件，或者说远多于 IDE 插件的开发，也很正常，大部分编程好用的功能，已有大牛实现了对应的插件，多数开发者没有一些特别的需求完全就没必要接触 vscode 插件开发。就如我一年前就想写 vscode 插件，但却迟迟拖到现在，其原因可能就这。

不过这类应用本就如此，就是不断翻阅文档，阅读前人的代码实现，再结合自身思路以完成最终目标。

## 参考文章

[VSCode 插件开发全攻略（一）概览 - 我是小茗同学 - 博客园 (cnblogs.com)](https://www.cnblogs.com/liuxianan/p/vscode-plugin-overview.html 'VSCode插件开发全攻略（一）概览 - 我是小茗同学 - 博客园 (cnblogs.com)')

[Extension API | Visual Studio Code Extension API](https://code.visualstudio.com/api)
