---
id: docusaurus-plugin
slug: /docusaurus-plugin
title: 插件
authors: kuizuo
---

这里我会列举我所用到的自定义插件，更多插件可看[社区精选 | Docusaurus](https://docusaurus.io/zh-CN/community/resources#community-plugins)

## plugin-baidu-analytics

[百度统计](https://tongji.baidu.com/web/welcome/login)

## plugin-baidu-push

[百度收录](https://ziyuan.baidu.com/dailysubmit/index)

主动推送代码

```javascript
(function(){
              var bp = document.createElement('script');
              var curProtocol = window.location.protocol.split(':')[0];
              if (curProtocol === 'https') {
                  bp.src = 'https://zz.bdstatic.com/linksubmit/push.js';
              }
              else {
                  bp.src = 'http://push.zhanzhang.baidu.com/push.js';
              }
              bp.defer = true;
              var s = document.getElementsByTagName("script")[0];
              s.parentNode.insertBefore(bp, s);
          })();
```

## plugin-matomo

[Matomo Analytics](https://matomo.org/) 站点统计，分析用户行为，停留时间。

## [plugin-pwa](https://docusaurus.io/zh-CN/docs/api/plugins/@docusaurus/plugin-pwa)

创建支持离线模式和应用安装的 PWA 文档站点

## [plugin-image-zoom](https://github.com/flexanalytics/plugin-image-zoom)

适用于 Docusaurus 的图像缩放插件

## plugin-content-blog

由于官方的plugin-content-blog插件没有将博客的所有标签数据传递给博客列表组件，也就是导致博客列表页面BlogListPage获取不到全局标签信息，所以这里对plugin-content-blog进行魔改，将tag信息添加至全局数据中。
