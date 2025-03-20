---
id: docusaurus-plugin
slug: /docusaurus-plugin
title: 插件
authors: kuizuo
---

在 `docusaurus.config.ts` 下的 plugins，可以看到所有插件以及插件配置。如下所示

```typescript title='docusaurus.config.ts' icon='logos:docusaurus'
plugins: [
    'docusaurus-plugin-image-zoom',
    'docusaurus-plugin-sass',
    '@docusaurus/plugin-ideal-image',
    ['docusaurus-plugin-baidu-tongji', { token: 'xxxxxxxxxxxxxxx' }],
    [
      '@docusaurus/plugin-pwa',
      {
        debug: process.env.NODE_ENV === 'development',
        offlineModeActivationStrategies: ['appInstalled', 'standalone', 'queryString'],
        pwaHead: [
          { tagName: 'link', rel: 'icon', href: '/img/logo.png' },
          { tagName: 'link', rel: 'manifest', href: '/manifest.json' },
          { tagName: 'meta', name: 'theme-color', content: '#12affa' },
        ],
      },
    ],
    [
      './src/plugin/plugin-content-blog', // 为了实现全局 blog 数据，必须改写 plugin-content-blog 插件
      {
        path: 'blog',
        editUrl: ({ locale, blogDirPath, blogPath, permalink }) =>
          `https://github.com/kuizuo/blog/edit/main/${blogDirPath}/${blogPath}`,
        editLocalizedFiles: false,
        blogDescription: '代码人生：编织技术与生活的博客之旅',
        blogSidebarCount: 10,
        blogSidebarTitle: 'Blogs',
        postsPerPage: 10,
        showReadingTime: true,
        readingTime: ({ content, frontMatter, defaultReadingTime }) =>
          defaultReadingTime({ content, options: { wordsPerMinute: 300 } }),
        feedOptions: {
          type: 'all',
          title: '愧怍',
          copyright: `Copyright © ${new Date().getFullYear()} 愧怍 Built with Docusaurus.<p><a href="http://beian.miit.gov.cn/" class="footer_lin">${beian}</a></p>`,
        },
      },
    ],
  ],
```

## [plugin-image-zoom](https://github.com/flexanalytics/plugin-image-zoom)

适用于 Docusaurus 的图像缩放插件。

## plugin-sass

支持 sass 预处理器

## plugin-baidu-tongji

使站点支持 [百度统计](https://tongji.baidu.com/web/welcome/login) ，这样你就能看到你的站点访客主要都在看哪些页面，以及行为记录，如下图所示。![image-20221204153015256](https://img.kuizuo.cn/image-20221204153015256.png)

同时还在 [Footer](https://github.com/kuizuo/blog/blob/main/src/theme/Footer/index.tsx#L3) 中添加了 [@vercel/analytics](https://github.com/vercel/analytics) 前提是需要本项目部署于 Vercel 上。

## [plugin-pwa](https://docusaurus.io/zh-CN/docs/api/plugins/@docusaurus/plugin-pwa)

创建支持离线模式和应用安装的 PWA 文档站点，就像下图这样。

![image-20221204153401244](https://img.kuizuo.cn/image-20221204153401244.png)

## plugin-content-blog

由于官方的 [plugin-content-blog](https://docusaurus.io/zh-CN/docs/api/plugins/@docusaurus/plugin-content-blog) 插件没有将有关博客的数据设置为全局，所以只能在博客列表页面 `BlogListPage` 组件中获取到，而由于本博客的某些组件需要使用到部分数据，因此这里对 `plugin-content-blog` 进行魔改，将 blog 信息添加至全局数据中，可在任意页面中都访问到所有博文的信息。

```typescript title='src/plugin/plugin-content-blog.ts'
async function blogPluginEnhanced(context, options) {
  const blogPluginInstance = await blogPlugin(context, options)

  return {
    ...blogPluginInstance,
    async contentLoaded({ content, allContent, actions }) {
      // Create default plugin pages
      await blogPluginInstance.contentLoaded({ content, allContent, actions })

      // Create your additional pages
      const { blogPosts, blogTags } = content
      const { setGlobalData } = actions

      setGlobalData({
        posts: blogPosts.slice(0, 10), // Only store 10 posts
        postNum: blogPosts.length,
        tagNum: Object.keys(blogTags).length,
      })
    },
  }
}
```

:::warning 这些数据可能会占据一定的空间，[点我](https://github.com/facebook/docusaurus/pull/7163#issuecomment-1096780257)查看详情 。

:::
