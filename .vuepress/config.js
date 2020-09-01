module.exports = {
  "title": "愧怍的小站",
  "description": "如果代码都解决不了的话,那可能真的解决不了",
  "dest": "public",
  "base": "/",
  locales: {
    '/': {
      lang: 'zh-CN'
    }
  },
  "head": [
    [
      "link",
      {
        "rel": "icon",
        "href": "/favicon.ico"
      }
    ],
    [
      "meta",
      {
        "name": "viewport",
        "content": "width=device-width,initial-scale=1,user-scalable=no"
      },
      {
        "name": "author",
        "content": "kuizuo"
      }
    ],
  ],
  "theme": "reco",
  themeConfig: {
    "nav": [{
      "text": "主页",
      "link": "/",
      "icon": "reco-home"
    },
    {
      "text": "时间线",
      "link": "/timeline/",
      "icon": "reco-date"
    },
    // {
    //   "text": "Docs",
    //   "icon": "reco-message",
    //   "items": [{
    //     "text": "vuepress-reco",
    //     "link": "/docs/theme-reco/"
    //   }, {
    //     "text": "aside",
    //     "link": "/docs/aside/"
    //   },
    //   ]
    // },
    {
      "text": "联系我",
      "icon": "reco-message",
      "items": [{
        "text": "GitHub",
        "link": "https://github.com/kuizuo",
        "icon": "reco-github"
      },
      {
        "text": "QQ",
        "link": "http://wpa.qq.com/msgrd?v=3&uin=911993023&site=qq&menu=yes",
        "icon": "reco-qq"
      }]
    }, {
      "text": "关于我",
      "icon": "reco-account",
      "link": "/about/",
    }
    ],
    // "sidebar": {
    //   "/docs/theme-reco/": [
    //     "",
    //     "theme",
    //     "plugin",
    //     "api"
    //   ]
    // },
    "type": "blog",
    "blogConfig": {
      "category": {
        "location": 3,
        "text": "分类"
      },
      "tag": {
        "location": 4,
        "text": "标签"
      }
    },
    "friendLink": [{
      "title": "午后南杂",
      "desc": "Enjoy when you can, and endure when you must.",
      "email": "1156743527@qq.com",
      "link": "https://www.recoluan.com"
    },
    {
      "title": "vuepress-theme-reco",
      "desc": "A simple and beautiful vuepress Blog & Doc theme.",
      "avatar": "https://vuepress-theme-reco.recoluan.com/icon_vuepress_reco.png",
      "link": "https://vuepress-theme-reco.recoluan.com"
    }
    ],
    "logo": "/logo.png",
    "search": true,
    "searchMaxSuggestions": 10,
    "lastUpdated": "Last Updated",
    "author": "愧怍",
    "authorAvatar": "/logo.png",
    "startYear": "2020",
    "sidebar": "auto",
    "sidebarDepth": "2",
    "mode": "light",
    "modePicker": true,
  },
  "markdown": {
    "lineNumbers": true,
    anchor: { permalink: false },
    // markdown-it-toc 的选项
    toc: { includeLevel: [1, 2] },
    extendMarkdown: md => {
      md.use(require("markdown-it-disable-url-encode"));
    }
  },
  "plugins": [
    ["vuepress-plugin-auto-sidebar", {
    }],
    ["vuepress-plugin-nuggets-style-copy", {
      copyText: "复制代码",
      tip: {
        content: "复制成功!"
      }
    }],
    // ['container', {
    //   type: 'navimg',
    //   before: info => `<div style="background-image:url(${info});height: 300px;" >`,
    //   after: '</div>',
    // }],

    // ["@vuepress-yard/vuepress-plugin-window", {
    //   title: "公告",
    //   contentInfo: {
    //     title: '欢迎加入QQ交流群 🎉🎉🎉',
    //     imgUrl: '/images/group.png',
    //     needImg: true, content: '不用图片的话 用这里的内容',
    //     contentStyle: {}

    //   },
    //   bottomInfo: {
    //     btnText: '', linkTo: ''
    //   },
    //   delayMount: 300,
    //   // closeOnce : false
    // }
    // ],
  ],
}