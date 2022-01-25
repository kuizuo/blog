import { sortBy } from '@site/src/utils/jsUtils';

export type Tag = {
  label: string;
  description: string;
  color: string;
};

export type TagType = 'favorite' | 'opensource' | 'product' | 'design' | 'javascript' | 'typescript' | 'nodejs';

export type Project = {
  title: string;
  description: string;
  preview?: any;
  website: string;
  source?: string | null;
  tags: TagType[];
};

export const Tags: Record<TagType, Tag> = {
  favorite: {
    label: 'Favorite',
    description: 'Our favorite Docusaurus sites that you must absolutely check-out!',
    color: '#e9669e',
  },
  opensource: {
    label: '开源',
    description: 'Open-Source Docusaurus sites can be useful for inspiration!',
    color: '#39ca30',
  },
  product: {
    label: '产品',
    description: 'Docusaurus sites associated to a commercial product!',
    color: '#dfd545',
  },
  design: {
    label: '设计',
    description: 'Beautiful Docusaurus sites, polished and standing out from the initial template!',
    color: '#a44fb7',
  },
  javascript: {
    label: 'JavaScript',
    description: 'JavaScript project',
    color: '#dfd545',
  },
  typescript: {
    label: 'TypeScript',
    description: 'JavaScript project',
    color: '#007acc',
  },
  nodejs: {
    label: 'NodeJS',
    description: 'NodeJS project',
    color: '#39ca30',
  },
};

const Projects: Project[] = [
  {
    title: '愧怍的小站',
    description: '基于Docusaurus v2 静态网站生成器实现个人博客',
    preview: require('./showcase/blog.png'),
    website: 'https://kuizuo.cn',
    source: 'https://github.com/kuizuo/blog',
    tags: ['opensource', 'design'],
  },
  {
    title: '资源导航',
    description: '学习编程中遇到的资源整合网站',
    preview: require('./showcase/nav.png'),
    website: 'https://nav.kuizuo.cn',
    source: 'https://github.com/kuizuo/code-nav',
    tags: ['opensource', 'javascript'],
  },
  // {
  //   title: 'kz-admin',
  //   description: '基于Vue + Vben + NestJs + TypeScript + TypeORM + MySql + Redis编写的一款前后端分离的权限管理系统',
  //   preview: require('./showcase/blog.png'),
  //   website: 'https://admin.kuizuo.cn',
  //   source: 'https://github.com/kuizuo/kz-admin',
  //   tags: ['opensource', 'typescript'],
  // },
  // {
  //   title: 'JavaScript混淆与还原',
  //   description: '基于AST语法树对JavaScript代码进行混淆与还原',
  //   preview: require('./showcase/js-de-obfuscator.png'),
  //   website: 'https://github.com/kuizuo/js-de-obfuscator',
  //   source: 'https://github.com/kuizuo/js-de-obfuscator',
  //   tags: ['opensource', 'javascript'],
  // },
  // {
  //   title: '链接管理系统',
  //   description: '一次性链接售卖卡密管理系统',
  //   preview: '',
  //   website: 'https://link.xiaoxin.vip',
  //   source: null,
  //   tags: ['product'],
  // },
];

export const TagList = Object.keys(Tags) as TagType[];
function sortProject() {
  let result = Projects;
  // Sort by site name
  // result = sortBy(result, (user) => user.title.toLowerCase());
  // Sort by favorite tag, favorites first
  // result = sortBy(result, (user) => !user.tags.includes('javascript'));
  return result;
}

export const sortedProjects = sortProject();
