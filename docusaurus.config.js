const { themes } = require('prism-react-renderer');

const path = require('path')
const beian = '闽ICP备2020017848号-2'

const announcementBarContent = `<a href="https://github.com/kuizuo/js-deobfuscator" target="_blank">JS 混淆代码还原, 感兴趣可以看看</a>`


export default async function createConfigAsync() {
  /** @type {import('@docusaurus/types').Config} */
  return {
    title: '愧怍的小站',
    url: 'https://kuizuo.cn',
    baseUrl: '/',
    favicon: 'img/favicon.ico',
    organizationName: 'kuizuo',
    projectName: 'blog',
    tagline: '道阻且长，行则将至',
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    themeConfig: {
      announcementBar: {
        id: 'announcementBar-3',
        content: announcementBarContent,
      },
      metadata: [
        {
          name: 'keywords',
          content: '愧怍, kuizuo',
        },
        {
          name: 'keywords',
          content: 'blog, javascript, typescript, node, react, vue, web',
        },
        {
          name: 'keywords',
          content: '编程爱好者, Web开发者, 写过爬虫, 学过逆向, 现在主攻ts全栈',
        },
      ],
      docs: {
        sidebar: {
          hideable: true,
        },
      },
      headTags: [
        {
          tagName: 'meta',
          attributes: {
            name: 'description',
            content: '愧怍的个人博客',
          },
        },
      ],
      navbar: {
        logo: {
          alt: '愧怍',
          src: 'img/logo.webp',
          srcDark: 'img/logo.webp',
        },
        hideOnScroll: true,
        items: [
          {
            label: '博客',
            position: 'right',
            to: 'blog',
          },
          {
            label: '项目',
            position: 'right',
            to: 'project',
          },
          {
            label: '更多',
            position: 'right',
            items: [
              { label: '归档', to: 'blog/archive' },
              { label: '笔记', to: 'docs/skill' },
              { label: '资源', to: 'resource' },
              { label: '友链', to: 'friends' },
              { label: '工具推荐', to: 'docs/tools' },
            ],
          },
          {
            type: 'localeDropdown',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: '学习',
            items: [
              { label: '博客', to: 'blog' },
              { label: '归档', to: 'blog/archive' },
              { label: '技术笔记', to: 'docs/skill' },
              { label: '实战项目', to: 'project' },
              { label: '前端示例', to: 'https://example.kuizuo.cn' },
            ],
          },
          {
            title: '社交媒体',
            items: [
              { label: '关于我', to: '/about' },
              { label: 'GitHub', href: 'https://github.com/kuizuo' },
              { label: 'Twitter', href: 'https://twitter.com/kuizuo' },
              {
                label: '掘金',
                href: 'https://juejin.cn/user/1565318510545901',
              },
              { label: 'Discord', href: 'https://discord.gg/M8cVcjDxkz' },
            ],
          },
          {
            title: '更多',
            items: [
              { label: '友链', position: 'right', to: 'friends' },
              { label: '导航', position: 'right', to: 'resource' },
              // { label: '我的站点', position: 'right', to: 'website' },
              {
                html: `<a href="https://docusaurus.io/zh-CN/" target="_blank"><img style="height:50px;margin-top:0.5rem" src="/img/buildwith.png" /><a/>`,
              },
            ],
          },
        ],
        copyright: `<p><a href="http://beian.miit.gov.cn/" >${beian}</a></p><p>Copyright © 2020 - PRESENT 愧怍 Built with Docusaurus.</p>`,
      },
      algolia: {
        appId: 'GV6YN1ODMO',
        apiKey: '50303937b0e4630bec4a20a14e3b7872',
        indexName: 'kuizuo',
      },
      giscus: {
        repo: 'kuizuo/blog',
        repoId: 'MDEwOlJlcG9zaXRvcnkzOTc2MjU2MTI=',
        category: 'General',
        categoryId: 'DIC_kwDOF7NJDM4CPK95',
        theme: 'light',
        darkTheme: 'dark',
      },
      socials: {
        github: 'https://github.com/kuizuo',
        twitter: 'https://twitter.com/kuizuo',
        juejin: 'https://juejin.cn/user/1565318510545901',
        csdn: 'https://blog.csdn.net/kuizuo12',
        qq: 'https://wpa.qq.com/msgrd?v=3&amp;uin=911993023&amp;site=qq',
        zhihu: 'https://www.zhihu.com/people/kuizuo',
        cloudmusic: 'https://music.163.com/#/user/home?id=1333010742',
        email: 'mailto:hi@kuizuo.cn',
      },
      prism: {
        theme: themes.oneLight,
        darkTheme: themes.oneDark,
        additionalLanguages: ['bash', 'json', 'java', 'php', 'rust', 'toml'],
        defaultLanguage: 'javascript',
        magicComments: [
          {
            className: 'theme-code-block-highlighted-line',
            line: 'highlight-next-line',
            block: { start: 'highlight-start', end: 'highlight-end' },
          },
          {
            className: 'code-block-error-line',
            line: 'This will error',
          },
        ],
      },
      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 4,
      },
      liveCodeBlock: {
        playgroundPosition: 'top',
      },
      zoom: {
        selector: '.markdown :not(em) > img',
        background: {
          light: 'rgb(255, 255, 255)',
          dark: 'rgb(50, 50, 50)',
        },
      },
    },
    presets: [
      [
        '@docusaurus/preset-classic',
        {
          docs: {
            path: 'docs',
            sidebarPath: 'sidebars.js',
          },
          blog: false,
          theme: {
            customCss: ['./src/css/custom.scss'],
          },
          sitemap: {
            changefreq: 'daily',
            priority: 0.5,
          },
          gtag: {
            trackingID: 'G-S4SD5NXWXF',
            anonymizeIP: true,
          },
          // debug: true,
        },
      ],
    ],
    plugins: [
      'docusaurus-plugin-image-zoom',
      'docusaurus-plugin-sass',
      path.resolve(__dirname, './src/plugin/plugin-baidu-tongji'),
      path.resolve(__dirname, './src/plugin/plugin-baidu-push'),
      [
        path.resolve(__dirname, './src/plugin/plugin-content-blog'), // 为了实现全局 blog 数据，必须改写 plugin-content-blog 插件
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
      [
        '@docusaurus/plugin-ideal-image',
        { disableInDev: false },
      ],
      [
        '@docusaurus/plugin-pwa',
        {
          debug: true,
          offlineModeActivationStrategies: [
            'appInstalled',
            'standalone',
            'queryString',
          ],
          pwaHead: [
            { tagName: 'link', rel: 'icon', href: '/img/logo.png' },
            { tagName: 'link', rel: 'manifest', href: '/manifest.json' },
            { tagName: 'meta', name: 'theme-color', content: '#12affa' },
          ],
        },
      ],
    ],
    stylesheets: [],
    i18n: {
      defaultLocale: 'zh-CN',
      locales: ['en', 'zh-CN'],
      localeConfigs: {
        en: {
          htmlLang: 'en-GB',
        },
      },
    },
  }
}
