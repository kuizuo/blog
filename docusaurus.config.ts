import type * as Preset from '@docusaurus/preset-classic'
import type { Config } from '@docusaurus/types'
import { themes } from 'prism-react-renderer'
import social from './data/social'

const config: Config = {
  title: 'Eliziane',
  url: 'https://el1ziane.vercel.app/',
  baseUrl: '/',
  favicon: 'img/favicon.ico',
  organizationName: 'Eliziane',
  projectName: 'blog',
  customFields: {
    bio: 'O caminho é longo e difícil, mas quem caminha, chega.',
    description:
      'Este é um blog pessoal criado por Eliziane, que compartilha conhecimento de desenvolvimento e projetos de programação. O site é construído com Docusaurus, um gerador de sites estáticos baseado em React.',
  },
  themeConfig: {
    image: 'img/og.png',
    metadata: [
      {
        name: 'author',
        content: 'Eliziane',
      },
      {
        name: 'keywords',
        content: 'blog, javascript, typescript, node, react, vue, web',
      },
      {
        name: 'keywords',
        content: 'programador, desenvolvedor web, já fiz crawlers, estudei engenharia reversa, foco em ts full-stack',
      },
    ],
    docs: {
      sidebar: {
        hideable: true,
      },
    },
    navbar: {
      logo: {
        alt: 'Eliziane',
        src: 'img/logo.webp',
        srcDark: 'img/logo.webp',
      },
      hideOnScroll: true,
      items: [
        { label: 'Blog', position: 'right', to: 'blog' },
        { label: 'Projetos', position: 'right', to: 'project' },
        { label: 'Sobre', position: 'right', to: 'about' },
        {
          label: 'Mais',
          position: 'right',
          items: [
            { label: 'Arquivos', to: 'blog/archive' },
            { label: 'Notas', to: 'docs/skill' },
            { label: 'Ferramentas', to: 'docs/tools' },
          ],
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Estudos',
          items: [
            { label: 'Blog', to: 'blog' },
            { label: 'Arquivos', to: 'blog/archive' },
            { label: 'Notas técnicas', to: 'docs/skill' },
            { label: 'Projetos práticos', to: 'project' },
          ],
        },
        {
          title: 'Mídias sociais',
          items: [
            { label: 'Sobre mim', to: '/about' },
            { label: 'GitHub', href: social.github.href },
            { label: 'LinkedIn', href: social.LinkedIn.href },
          ],
        },
        {
          items: [
            {
              html: `
                <a href="https://docusaurus.io" target="_blank" rel="noreferrer noopener">
                  <img src="/img/buildwith.png" alt="build with docusaurus" width="120" height="50"/>
                </a>
                `,
            },
          ],
        },
      ],
      copyright: `
        <p style="margin-bottom: 0;"></p>
        <p style="display: inline-flex; align-items: center;"><img style="height:20px;margin-right: 0.5rem;" height="20"/></p>
        <p>ᓚᘏᗢ 2025 - ${new Date().getFullYear()} | Built with Docusaurus.</p>
        `,
    },
    algolia: {
      appId: 'GV6YN1ODMO',
      apiKey: '50303937b0e4630bec4a20a14e3b7872',
      indexName: 'eliziane',
    },
    prism: {
      theme: themes.oneLight,
      darkTheme: themes.oneDark,
      additionalLanguages: ['bash', 'json', 'java', 'python', 'php', 'graphql', 'rust', 'toml', 'protobuf', 'diff'],
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
    },
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
          customCss: ['./src/css/custom.css', './src/css/tweet-theme.css'],
        },
        sitemap: {
          priority: 0.5,
        },
        gtag: {
          trackingID: 'G-S4SD5NXWXF',
          anonymizeIP: true,
        },
        debug: process.env.NODE_ENV === 'development',
      } satisfies Preset.Options,
    ],
  ],
  plugins: [
    'docusaurus-plugin-image-zoom',
    '@docusaurus/plugin-ideal-image',
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
      'vercel-analytics',
      {
        debug: process.env.NODE_ENV === 'development',
        mode: 'auto',
      },
    ],
    [
      './src/plugin/plugin-content-blog',
      {
        path: 'blog',
        editUrl: ({ locale, blogDirPath, blogPath, permalink }) =>
          `https://github.com/kuizuo/blog/edit/main/${blogDirPath}/${blogPath}`,
        editLocalizedFiles: false,
        blogDescription: 'Vida de código: uma jornada de blog entre tecnologia e vida',
        blogSidebarCount: 10,
        blogSidebarTitle: 'Postagens do blog',
        postsPerPage: 12,
        showReadingTime: true,
        readingTime: ({ content, frontMatter, defaultReadingTime }) =>
          defaultReadingTime({ content, options: { wordsPerMinute: 300 } }),
        feedOptions: {
          type: 'all',
          title: 'Eliziane',
          description: 'feedId:41215011978385457+userId:41840354283324416',
          copyright: `Copyright © ${new Date().getFullYear()} Eliziane Built with Docusaurus.<p></p>`,
        },
      },
    ],
    async function tailwindcssPlugin() {
      return {
        name: 'docusaurus-tailwindcss',
        configurePostCss(postcssOptions) {
          postcssOptions.plugins.push(require('tailwindcss'))
          postcssOptions.plugins.push(require('autoprefixer'))
          return postcssOptions
        },
      }
    },
    async function injectMotto() {
      return {
        name: 'docusaurus-motto',
        injectHtmlTags() {
          return {
            headTags: [
              {
                tagName: 'script',
                innerHTML: `(${function () {
                  console.log(
                    '%c Kz Blog %c https://github.com/kuizuo/blog',
                    'color: #fff; margin: 1em 0; padding: 5px 0; background: #12affa;',
                    'margin: 1em 0; padding: 5px 0; background: #efefef;',
                  )

                  const motto = `
Este website é alimentado pelo Kz Blog.
Escrito com Docusaurus, programando com amor.
--------
Ame o que você faz e faça o que você ama.
`

                  if (document.firstChild?.nodeType !== Node.COMMENT_NODE) {
                    document.prepend(document.createComment(motto))
                  }
                }.toString()})();`,
              },
            ],
          }
        },
      }
    },
  ],
  headTags: [
    {
      tagName: 'meta',
      attributes: {
        name: 'description',
        content: 'Blog pessoal de Eliziane',
      },
    },
  ],
  stylesheets: [
    'https://cdn.jsdelivr.net/npm/misans@4.0.0/lib/Normal/MiSans-Normal.min.css',
    'https://cdn.jsdelivr.net/npm/misans@4.0.0/lib/Normal/MiSans-Medium.min.css',
    'https://cdn.jsdelivr.net/npm/misans@4.0.0/lib/Normal/MiSans-Semibold.min.css',
  ],
  i18n: {
    defaultLocale: 'pt-BR',
    locales: ['pt-BR'],
  },
  onBrokenLinks: 'warn',
}

export default config
