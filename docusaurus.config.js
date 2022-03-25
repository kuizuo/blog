// @ts-check
const path = require('path')
const beian = '闽ICP备2020017848号-2'
const friendLinks = [
  {
    label: '峰华前端工程师',
    to: 'https://zxuqian.cn/',
  },
]
/** @type {import('@docusaurus/types').Config} */
const config = {
  title: '愧怍的小站',
  titleDelimiter: '-',
  url: 'https://kuizuo.cn',
  baseUrl: '/',
  favicon: 'img/favicon.ico',
  organizationName: 'kuizuo', // Usually your GitHub org/user name.
  projectName: 'kuizuo.cn', // Usually your repo name.
  /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
  themeConfig: {
    image: 'img/kuizuo.jpg',
    announcementBar: {
      id: 'announcementBar-2', // Any value that will identify this message.
      content: `代码能重写，人不能重来`,
    },
    metadata: [{ name: 'keywords', content: 'blog, javascript, typescript, python ,node, react, vue, web, 前端, 后端, 愧怍' }],
    hideableSidebar: true,
    navbar: {
      title: '愧怍',
      logo: {
        alt: '愧怍',
        src: 'img/logo.webp',
        srcDark: 'img/logo.webp',
      },
      items: [
        {
          label: '标签',
          to: 'tags',
          position: 'right',
        },
        {
          label: '归档',
          to: 'archive',
          position: 'right',
        },
        {
          label: '学习',
          position: 'right',
          items: [
            {
              label: '技术笔记',
              to: 'docs/skill/',
            },
            // {
            //   label: "个人推荐",
            //   to: "docs/recommend",
            // },
          ],
        },
        {
          label: '小工具',
          position: 'right',
          items: [
            {
              label: '资源导航',
              to: '/resources', // 'https://nav.kuizuo.cn'
            },
            {
              label: 'JS代码混淆与还原',
              to: '/deobfuscator', // 'https://deobfuscator.kuizuo.cn'
            },
            {
              label: 'CyberChef在线加解密',
              to: 'http://cipher.kuizuo.cn', // 'http://cipher.kuizuo.cn'
            },
            {
              label: '愧怍在线工具',
              to: 'http://tools.kuizuo.cn', // 'http://tools.kuizuo.cn'
            },
          ],
        },
        {
          label: '实战项目',
          position: 'right',
          to: '/project',
        },
      ],
    },
    algolia: {
      apiKey: '87223cb5a5ff37c4dbbb616812c65a59',
      appId: '2NBW5YNFON',
      indexName: 'kuizuo',
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: '学习',
          items: [
            {
              label: '技术博客',
              to: '/#homepage_blogs',
            },
            {
              label: '技术笔记',
              to: 'docs/skill',
            },
            {
              label: '实战项目',
              to: 'project',
            },
          ],
        },
        {
          title: '社交媒体',
          items: [
            {
              label: '首页',
              to: '/',
            },
            {
              label: '关于我',
              to: '/about',
            },
            {
              label: 'GitHub',
              href: 'https://github.com/kuizuo',
            },
            {
              label: '掘金',
              href: 'https://juejin.cn/user/1565318510545901',
            },
          ],
        },
        {
          title: '友情链接',
          items: friendLinks,
        },
      ],
      copyright: `<p>Copyright © ${new Date().getFullYear()} 愧怍 Built with Docusaurus.</p><p><a href="http://beian.miit.gov.cn/" >${beian}</a>`,
      //</p><a rel="license" href="http://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons License" style="border-width:0" src="/img/creative-commons-license-icon.png" /></a><br />本站所有内容遵循 <a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/deed.zh-Hans" >CC BY-NC 4.0 协议</a>，转载须注明署名和出处，且不可用于商业用途。若与其他同步平台协议冲突，以本网站为准。
    },
    prism: {
      theme: require('prism-react-renderer/themes/github'),
      darkTheme: require('prism-react-renderer/themes/vsDark'),
      additionalLanguages: ['java', 'php'],
      // defaultLanguage: "javascript",
    },
    tableOfContents: {
      minHeadingLevel: 2,
      maxHeadingLevel: 4,
    },
    zoomSelector: '.markdown :not(em) > img',
    liveCodeBlock: {
      playgroundPosition: 'top',
    },
    // googleAnalytics: {
    //   trackingID: "UA-118572241-1",
    //   anonymizeIP: true, // Should IPs be anonymized?
    // },
    // gtag: {
    //   trackingID: "G-6PSESJX0BM",
    //   // Optional fields.
    //   anonymizeIP: true, // Should IPs be anonymized?
    // },
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          // editUrl: "https://github.com/kuizuo/kuizuo.cn/tree/master",
          // remarkPlugins: [require("remark-math")],
          // rehypePlugins: [require("rehype-katex")],
          // showLastUpdateAuthor: true,
          // showLastUpdateTime: true,
        },
        blog: {
          path: 'blog',
          routeBasePath: '/',
          blogSidebarTitle: '近期文章',
          blogSidebarCount: 5,
          postsPerPage: 10,
          // remarkPlugins: [require("remark-math")],
          // rehypePlugins: [require("rehype-katex")],
          feedOptions: {
            type: 'all',
            title: '愧怍',
            copyright: `Copyright © ${new Date().getFullYear()} 愧怍 Built with Docusaurus.<p><a href="http://beian.miit.gov.cn/" class="footer_lin">${beian}</a></p>`,
          },
        },
        theme: {
          customCss: [require.resolve('./src/css/custom.css')],
        },
        sitemap: {
          changefreq: 'daily',
          priority: 0.5,
        },
        // debug: true,
      }),
    ],
  ],
  themes: ['@docusaurus/theme-live-codeblock'],
  plugins: [
    path.resolve(__dirname, './src/plugin/plugin-baidu-analytics'),
    path.resolve(__dirname, './src/plugin/plugin-baidu-push'),
    // path.resolve(__dirname, "./src/plugin/plugin-onesignal-push"),
    // "docusaurus2-dotenv",
    '@docusaurus/plugin-ideal-image',
    path.resolve(__dirname, './src/plugin/plugin-image-zoom'),
    path.resolve(__dirname, './src/plugin/plugin-latest-docs'),
    // [
    //   "@easyops-cn/docusaurus-search-local",
    //   {
    //     hashed: true,
    //     // indexPages: true,
    //     blogRouteBasePath: "/",
    //     language: ["en", "zh"],
    //   },
    // ],
    [
      '@docusaurus/plugin-pwa',
      {
        debug: true,
        offlineModeActivationStrategies: ['appInstalled', 'standalone', 'queryString'],
        pwaHead: [
          {
            tagName: 'link',
            rel: 'icon',
            href: '/img/kuizuo.jpg',
          },
          {
            tagName: 'link',
            rel: 'manifest',
            href: '/manifest.json', // 您的 PWA Manifest
          },
          {
            tagName: 'meta',
            name: 'theme-color',
            content: 'rgb(51 139 255)',
          },
        ],
      },
    ],
  ],
  stylesheets: [
    // {
    //   rel: "preconnect",
    //   href: "https://fonts.gstatic.com",
    //   type: "text/css",
    // },
    /* {
      href: "/katex/katex.min.css",
      type: "text/css",
      integrity:
        "sha384-AfEj0r4/OFrOo5t7NnNe46zW/tFgW6x/bCJG8FqQCEo3+Aro6EYUG4+cU+KJWu/X",
      crossorigin: "anonymous",
    }, */
    // {
    //   href: "https://fonts.font.im/css?family=Raleway:500,700&display=swap",
    //   type: "text/css",
    //   rel: "stylesheet",
    // },
    // {
    //   href: "https://fonts.googleapis.com/css2?family=Fira+Code&display=swap",
    //   type: "text/css",
    //   rel: "stylesheet",
    // },
  ],
  i18n: {
    defaultLocale: 'zh-CN',
    locales: ['zh-CN'],
  },
  onBrokenLinks: 'ignore',
}

module.exports = config
