import path from 'node:path'
import type { Config } from '@docusaurus/types'
import type * as Preset from '@docusaurus/preset-classic'
import { themes } from 'prism-react-renderer'
import { Social } from './src/components/SocialLinks'
import { GiscusConfig } from './src/components/Comment'

const beian = '闽ICP备2020017848号-2'
const beian1 = '闽公网安备35021102000847号'

const config: Config = {
  title: '愧怍的小站',
  url: 'https://kuizuo.cn',
  baseUrl: '/',
  favicon: 'img/favicon.ico',
  organizationName: 'kuizuo',
  projectName: 'blog',
  tagline: '道阻且长，行则将至',
  themeConfig: {
    // announcementBar: {
    //   id: 'announcementBar-3',
    //   content: ``,
    // },
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
            {
              html: `
                <a href="https://docusaurus.io/zh-CN/" target="_blank" rel="noreferrer noopener">
                  <img src="/img/buildwith.png" alt="build with docusaurus" width="120" height="50"/>
                <a/>
                `,
            },
          ],
        },
      ],
      copyright: `
        <p style="margin-bottom: 0;"><a href="http://beian.miit.gov.cn/">${beian}</a></p>
        <p style="display: inline-flex; align-items: center;"><img style="height:20px;margin-right: 0.5rem;" src="/img/police.png" alt="police" height="20"/><a href="http://www.beian.gov.cn/portal/registerSystemInfo?recordcode=${beian1.match(
          /\d+/,
        )?.[0]}" >${beian1}</a></p>
        <p>Copyright © 2020 - PRESENT 愧怍 Built with Docusaurus.</p>
        `,
    },
    algolia: {
      appId: 'GV6YN1ODMO',
      apiKey: '50303937b0e4630bec4a20a14e3b7872',
      indexName: 'kuizuo',
    },
    prism: {
      theme: themes.oneLight,
      darkTheme: themes.oneDark,
      additionalLanguages: [
        'bash',
        'json',
        'java',
        'python',
        'php',
        'graphql',
        'rust',
        'toml',
        'protobuf',
      ],
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
    giscus: {
      repo: 'kuizuo/blog',
      repoId: 'MDEwOlJlcG9zaXRvcnkzOTc2MjU2MTI=',
      category: 'General',
      categoryId: 'DIC_kwDOF7NJDM4CPK95',
      theme: 'light',
      darkTheme: 'dark_dimmed',
    } satisfies Partial<GiscusConfig>,
    socials: {
      github: 'https://github.com/kuizuo',
      twitter: 'https://twitter.com/kuizuo',
      juejin: 'https://juejin.cn/user/1565318510545901',
      csdn: 'https://blog.csdn.net/kuizuo12',
      qq: 'https://wpa.qq.com/msgrd?v=3&amp;uin=911993023&amp;site=qq',
      zhihu: 'https://www.zhihu.com/people/kuizuo',
      cloudmusic: 'https://music.163.com/#/user/home?id=1333010742',
      email: 'mailto:hi@kuizuo.cn',
    } satisfies Social,
    tableOfContents: {
      minHeadingLevel: 2,
      maxHeadingLevel: 4,
    },
    liveCodeBlock: { playgroundPosition: 'top' },
    zoom: {
      selector: '.markdown :not(em) > img',
      background: {
        light: 'rgb(255, 255, 255)',
        dark: 'rgb(50, 50, 50)',
      },
    },
  } satisfies Preset.ThemeConfig,
  presets: [
    [
      'classic',
      {
        docs: {
          path: 'docs',
          sidebarPath: 'sidebars.ts',
        },
        blog: false,
        theme: {
          customCss: ['./src/css/custom.scss'],
        },
        sitemap: {
          priority: 0.5,
        },
        gtag: {
          trackingID: 'G-S4SD5NXWXF',
          anonymizeIP: true,
        },
        // debug: true,
      } satisfies Preset.Options,
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
    ['@docusaurus/plugin-ideal-image', { disableInDev: false }],
    [
      '@docusaurus/plugin-pwa',
      {
        debug: true,
        offlineModeActivationStrategies: ['appInstalled', 'standalone', 'queryString'],
        pwaHead: [
          { tagName: 'link', rel: 'icon', href: '/img/logo.png' },
          { tagName: 'link', rel: 'manifest', href: '/manifest.json' },
          { tagName: 'meta', name: 'theme-color', content: '#12affa' },
        ],
      },
    ],
  ],
  headTags: [
    {
      tagName: 'meta',
      attributes: {
        name: 'description',
        content: '愧怍的个人博客',
      },
    },
  ],
  stylesheets: ['https://cdn.jsdelivr.net/npm/misans@4.0.0/lib/Normal/MiSans-Normal.min.css'],
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

export default config
