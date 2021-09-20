const path = require('path');
const beian = '闽ICP备2020017848号-2';
const friendLinks = [
  {
    label: '峰华前端工程师',
    to: 'https://zxuqian.cn/',
  },
];

module.exports = {
  title: '愧怍的小站',
  // tagline:
  titleDelimiter: '-',
  url: 'https://kuizuo.cn',
  baseUrl: '/',
  favicon: 'img/favicon.ico',
  organizationName: 'kuizuo', // Usually your GitHub org/user name.
  projectName: 'kuizuo.cn', // Usually your repo name.
  themeConfig: {
    image: 'img/kuizuo.jpg',
    announcementBar: {
      /*       id: "feature_release", // Any value that will identify this message.
            content: `更新<a href='/docs/skill/browser/js-web-animations-api'>《与 CSS Keyframes 媲美的原生 JS 高性能动画 API 教程》配套文本</a>`,
            backgroundColor: "#fafbfc", // Defaults to `#fff`.
            textColor: "#091E42", // Defaults to `#000`. */
    },
    hideableSidebar: true,
    navbar: {
      title: '愧怍',
      logo: {
        alt: '愧怍',
        src: 'img/logo.webp',
        srcDark: 'img/logo.webp',
      },
      items: [
        // {
        //   label: '博客',
        //   to: '/#homepage_blogs',
        //   position: 'right',
        // },
        {
          label: '随笔',
          to: 'essay',
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
        /*         {
                  label: "实战项目",
                  position: "right",
                  to: "/project",
                },*/
        {
          label: '资源导航',
          position: 'right',
          to: '/resources', // 'https://nav.kuizuo.cn'
        },
        {
          label: '关于我',
          position: 'right',
          to: '/about',
        },
        // {
        //   href: 'https://github.com/kuizuo/kuizuo.cn',
        //   label: '本站源码',
        //   position: 'right',
        // },
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
              label: '技术笔记',
              to: 'docs/skill',
            },
            {
              label: '实战项目',
              to: 'project',
            },
            {
              label: '资源导航',
              to: 'resources',
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
      // additionalLanguages: ['powershell','vue'],
      // defaultLanguage: "javascript",
    },
    zoomSelector: '.markdown :not(em) > img',
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
      {
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          // editUrl: "https://github.com/kuizuo/kuizuo.cn/tree/master",
          // remarkPlugins: [require("remark-math")],
          // rehypePlugins: [require("rehype-katex")],
          showLastUpdateTime: true,
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
      },
    ],
  ],
  // themes: ["@docusaurus/theme-live-codeblock"],
  plugins: [
    path.resolve(__dirname, './src/plugin/plugin-baidu-analytics'),
    path.resolve(__dirname, './src/plugin/plugin-baidu-push'),
    // path.resolve(__dirname, "./src/plugin/plugin-onesignal-push"),
    '@docusaurus/plugin-ideal-image',
    'plugin-image-zoom',
    path.resolve(__dirname, './src/plugin/plugin-latest-docs'),
    // "docusaurus2-dotenv",
    // [
    //   '@docusaurus/plugin-content-blog',
    //   {
    //     id: 'first-blog',
    //     routeBasePath: 'blog',
    //     path: './blog',
    //     blogSidebarTitle: '近期文章',
    //   },
    // ],
    [
      '@docusaurus/plugin-content-blog',
      {
        id: 'second-blog',
        routeBasePath: 'essay',
        path: './essay',
        blogSidebarTitle: '近期文章',
      },
    ],
    // [
    //   "@easyops-cn/docusaurus-search-local",
    //   {
    //     hashed: true,
    //     // indexPages: true,
    //     blogRouteBasePath: "/",
    //     language: ["en", "zh"],
    //   },
    // ],
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
};
