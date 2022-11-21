export const projects: Project[] = [
  {
    title: '愧怍的小站',
    description: '基于Docusaurus v2 静态网站生成器实现个人博客',
    preview: '/img/project/blog.png',
    website: 'https://kuizuo.cn',
    source: 'https://github.com/kuizuo/blog',
    tags: ['opensource', 'design', 'favorite'],
    type: 'web',
  },
  {
    title: 'kz-admin',
    description: '基于NestJs + TypeScript + TypeORM + Redis + MySql + Vben Admin编写的一款前后端分离的权限管理系统',
    preview: '/img/project/kz-admin.png',
    website: 'https://admin.kuizuo.cn',
    source: 'https://github.com/kuizuo/kz-admin',
    tags: ['opensource', 'favorite', 'product', 'large'],
    type: 'web',
  },
  {
    title: 'KZ-API',
    description: '基于Nuxt3 + Vite3 + Vue3 + UnoCSS搭建的API接口服务网站',
    preview: '/img/project/kz-api.png',
    website: 'https://api.kuizuo.cn',
    source: 'https://github.com/kuizuo/api-service',
    tags: ['opensource', 'favorite', 'product'],
    type: 'web',
  },
  {
    title: 'Protocol',
    description: '🧪 一个用于快速复现请求协议的 Web 开发模板。',
    preview: '/img/project/protocol.png',
    website: 'https://protocol.kuizuo.cn',
    source: 'https://github.com/kuizuo/protocol',
    tags: ['opensource', 'favorite'],
    type: 'web',
  },
  {
    title: '前端示例代码库',
    description: '整理前端样式和功能的实现代码，可以用来寻找灵感或直接使用示例中的代码',
    preview: '/img/project/example-website.png',
    website: 'https://example.kuizuo.cn',
    source: 'https://github.com/kuizuo/example',
    tags: ['opensource', 'design'],
    type: 'web',
  },
  {
    title: 'Vitesse Nuxt3 Strapi',
    description: '一个 Vitesse Nuxt3 Strapi 的模板，灵感来源 Vitesse',
    preview: '/img/project/vitesse-nuxt3-strapi.png',
    website: 'https://vitesse-nuxt3-strapi.vercel.app',
    source: 'https://github.com/kuizuo/vitesse-nuxt3-strapi',
    tags: ['opensource'],
    type: 'web',
  },
  {
    title: 'JS代码混淆与还原',
    description: '基于Babel的AST操作对JavaScript代码混淆与还原的网站',
    preview: '/img/project/js-de-obfuscator.png',
    website: 'https://deobfuscator.vercel.app',
    source: 'https://github.com/kuizuo/js-de-obfuscator',
    tags: ['opensource'],
    type: 'web',
  },
  {
    title: 'VScode-extension',
    description: 'vscode 插件的样品',
    preview: '/img/project/vscode-extension.png',
    website: 'https://marketplace.visualstudio.com/items?itemName=kuizuo.vscode-extension-sample',
    source: 'https://github.com/kuizuo/vscode-extension',
    tags: ['opensource'],
    type: 'web',
  },
  {
    title: 'Link-admin',
    description: '基于 kz-admin 编写的一次性充值链接销售系统',
    preview: '/img/project/link-admin.png',
    website: 'http://link.kuizuo.cn',
    tags: ['product', 'large'],
    type: 'other',
  },
  {
    title: 'ocr-admin',
    description: '基于 ddddocr 与 kz-admin 搭建的图像识别后台系统',
    preview: '/img/project/ocr-admin.png',
    website: 'http://ocr.kuizuo.cn',
    tags: ['product', 'large'],
    type: 'other',
  },
  // {
  //   title: '卡密系统',
  //   description: '基于 Protocol 搭建的一个卡密充值系统',
  //   preview: '/img/project/ticket-system.png',
  //   website: 'https://ticket.kuizuo.cn',
  //   source: 'https://github.com/kuizuo/protocol/tree/ticket',
  //   tags: ['opensource', 'product'],
  //   type: 'other',
  // },
  // {
  //   title: 'vscode-settings',
  //   description: '我的 Vscode 相关配置',
  //   website: 'https://github/kuizuo/vscode-settings',
  //   tags: ['opensource', 'personal'],
  //   type: 'personal'
  // },
  {
    title: '@kuizuo/http',
    description: '基于 Axios 封装的 HTTP 类库',
    website: 'https://www.npmjs.com/package/@kuizuo/http',
    tags: ['opensource', 'personal'],
    type: 'personal'
  },
  {
    title: '@kuizuo/utils',
    description: '整理JavaScript / TypeScript的相关工具函数',
    website: 'https://www.npmjs.com/package/@kuizuo/utils',
    tags: ['opensource', 'personal'],
    type: 'personal'
  },
  {
    title: '@kuizuo/eslint-config',
    description: 'WebSocket远程调用浏览器函数',
    website: 'https://github.com/kuizuo/eslint-config',
    tags: ['opensource', 'personal'],
    type: 'personal'
  },
  {
    title: 'browser-rpc',
    description: 'WebSocket远程调用浏览器函数',
    website: 'https://github.com/kuizuo/rpc-browser',
    tags: ['opensource'],
    type: 'personal'
  },
  // {
  //   title: 'mini-vue',
  //   description: '🙃mini vue3 实现',
  //   website: 'https://github.com/kuizuo/mini-vue',
  //   tags: ['opensource'],
  //   type: 'personal'
  // },
]

export type Tag = {
  label: string;
  description: string;
  color: string;
};

export type TagType =
  | 'favorite'
  | 'opensource'
  | 'product'
  | 'design'
  | 'large'
  | 'personal';

export type ProjectType =
  | 'personal'
  | 'web'
  | 'app'
  | 'other';

export type Project = {
  title: string;
  description: string;
  preview?: any;
  website: string;
  source?: string | null;
  tags: TagType[];
  type: ProjectType
};

export const Tags: Record<TagType, Tag> = {
  favorite: {
    label: '喜爱',
    description: '我最喜欢的网站，一定要去看看!',
    color: '#e9669e',
  },
  opensource: {
    label: '开源',
    description: '开源项目可以提供灵感!',
    color: '#39ca30',
  },
  product: {
    label: '产品',
    description: '与产品相关的项目!',
    color: '#dfd545',
  },
  design: {
    label: '设计',
    description: '设计漂亮的网站!',
    color: '#a44fb7',
  },
  large: {
    label: '大型',
    description: '大型项目，原多于平均数的页面',
    color: '#8c2f00',
  },
  personal: {
    label: '个人',
    description: '个人项目',
    color: '#12affa',
  },
};

export const TagList = Object.keys(Tags) as TagType[];

export const groupByProjects = projects.reduce((group, project) => {
  const { type } = project;
  group[type] = group[type] ?? [];
  group[type].push(project);
  return group;
},
  {} as Record<ProjectType, Project[]>
)

