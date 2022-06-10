// @ts-check
const path = require('path')
const beian = '闽ICP备2020017848号-2'

const announcementBarContent = `新增基于<a href='https://pypi.org/project/ddddocr/'>ddddocr</a>实现<a href='https://ocr.kuizuo.cn'>图像识别后台系统</a>`
/** @type {import('@docusaurus/types').Config} */
const config = {
  title: '愧怍的小站',
  titleDelimiter: '-',
  url: 'https://kuizuo.cn',
  baseUrl: '/',
  favicon: 'img/favicon.ico',
  organizationName: 'kuizuo',
  projectName: 'blog',
  tagline: '记录所学知识，领略编程之美',
  /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
  themeConfig: {
    image: 'img/logo.png',
    announcementBar: {
      id: 'announcementBar-3',
      content: announcementBarContent,
    },
    metadata: [
      {
        name: 'keywords',
        content: '愧怍, kuizuo, blog, javascript, typescript, python ,node, react, vue, web, 前端, 后端',
      },
    ],
    docs: {
      sidebar: {
        hideable: true,
      }
    },
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
            {
              label: '工具推荐',
              to: 'docs/tools/',
            },
          ],
        },
        {
          label: '小工具',
          position: 'right',
          items: [
            {
              label: '编程网址导航',
              to: 'https://nav.kuizuo.cn',
            },
            {
              label: 'JS代码混淆与还原',
              to: 'https://deobfuscator.kuizuo.cn',
            },
            {
              label: 'CyberChef在线加解密',
              to: 'https://cipher.kuizuo.cn',
            },
            {
              label: '愧怍在线工具',
              to: 'https://tools.kuizuo.cn',
            },
            {
              label: '愧怍网盘',
              to: 'https://pan.kuizuo.cn',
            },
          ],
        },
        {
          label: '友链',
          position: 'right',
          to: 'friends',
        },
        {
          label: '项目',
          position: 'right',
          to: '/project',
        },
      ],
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
          title: '更多',
          items: [{
            label: '...',
            to: '/',
          }],
        },
      ],
      copyright: `<p>Copyright © ${new Date().getFullYear()} 愧怍 Built with Docusaurus.</p><p><a href="http://beian.miit.gov.cn/" >${beian}</a></p>`,
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
    algolia: {
      apiKey: '87223cb5a5ff37c4dbbb616812c65a59',
      appId: '2NBW5YNFON',
      indexName: 'kuizuo',
    },
    zoom: {
      selector: '.markdown :not(em) > img',
      background: {
        light: 'rgb(255, 255, 255)',
        dark: 'rgb(50, 50, 50)'
      },
      config: {}
    },
    matomo: {
      matomoUrl: 'https://matomo.kuizuo.cn',
      siteId: '1',
      phpLoader: 'matomo.php',
      jsLoader: 'matomo.js',
    },
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
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: 'docs',
          sidebarPath: 'sidebars.js',
        },
        blog: {
          path: 'blog',
          routeBasePath: '/',
          blogSidebarTitle: '近期文章',
          blogSidebarCount: 5,
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
    'docusaurus-plugin-matomo',
    'docusaurus-plugin-image-zoom',
    [
      '@docusaurus/plugin-ideal-image', {
        disableInDev: false,
      }
    ],
    [
      '@docusaurus/plugin-pwa',
      {
        debug: true,
        offlineModeActivationStrategies: ['appInstalled', 'standalone', 'queryString'],
        pwaHead: [
          {
            tagName: 'link',
            rel: 'icon',
            href: '/img/logo.png',
          },
          {
            tagName: 'link',
            rel: 'manifest',
            href: '/manifest.json',
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
    defaultLocale: 'zh',
    locales: ['zh'],
  },
  onBrokenLinks: 'ignore',
}

module.exports = config
