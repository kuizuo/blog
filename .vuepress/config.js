module.exports = {
  "title": "愧怍的小站",
  "description": "如果代码都解决不了的话,那可能真的解决不了",
  "dest": "public",
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
    ]
  ],
  "theme": "reco",
  "themeConfig": {
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
    {
      "text": "Docs",
      "icon": "reco-message",
      "items": [{
        "text": "vuepress-reco",
        "link": "/docs/theme-reco/"
      }]
    },
    {
      "text": "Contact",
      "icon": "reco-message",
      "items": [{
        "text": "GitHub",
        "link": "https://github.com/recoluan",
        "icon": "reco-github"
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
    "author": "kuizuo",
    "authorAvatar": "/logo.png",
    "record": "xxxx",
    "startYear": "2017",
    "sidebar": "auto",
    "sidebarDepth": "2",
    "mode": "light",
    "modePicker": true,

  },
  "markdown": {
    "lineNumbers": true
  },
  "plugins": {
    "vuepress-plugin-auto-sidebar": {}
  },
}