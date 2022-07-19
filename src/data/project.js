"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sortedProjects = exports.TagList = exports.Tags = void 0;
exports.Tags = {
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
    javascript: {
        label: 'JavaScript',
        description: 'JavaScript 项目',
        color: '#dfd545',
    },
};
const Projects = [
    {
        title: '愧怍的小站',
        description: '基于Docusaurus v2 静态网站生成器实现个人博客',
        preview: 'https://img.kuizuo.cn/blog.png',
        website: 'https://kuizuo.cn',
        source: 'https://github.com/kuizuo/blog',
        tags: ['opensource', 'design', 'favorite'],
    },
    {
        title: 'kz-admin',
        description: '基于NestJs + TypeScript + TypeORM + Redis + MySql + Vben Admin编写的一款前后端分离的权限管理系统',
        preview: 'https://img.kuizuo.cn/kz-admin.png',
        website: 'https://admin.kuizuo.cn',
        source: 'https://github.com/kuizuo/kz-nest-admin',
        tags: ['opensource', 'favorite', 'product'],
    },
    {
        title: 'KZ-API',
        description: '基于Nuxt3 + Vite3 + Vue3 + UnoCSS搭建的API接口服务网站',
        preview: 'https://img.kuizuo.cn/KZ%20API.png',
        website: 'https://api.kuizuo.cn',
        source: 'https://github.com/kuizuo/api-service',
        tags: ['opensource', 'favorite', 'product'],
    },
    {
        title: 'VScode-extension',
        description: 'vscode 插件的样品',
        preview: 'https://img.kuizuo.cn/vscode-extension.png',
        website: 'https://marketplace.visualstudio.com/items?itemName=kuizuo.vscode-extension-sample',
        source: 'https://github.com/kuizuo/vscode-extension',
        tags: ['opensource', 'javascript'],
    },
    {
        title: 'ocr-admin',
        description: '基于ddddocr与kz-admin搭建的图像识别后台系统',
        preview: 'https://img.kuizuo.cn/ocr-admin.png',
        website: 'https://ocr.kuizuo.cn',
        source: '',
        tags: ['product'],
    },
    {
        title: 'JS代码混淆与还原',
        description: '基于Babel的AST操作对JavaScript代码混淆与还原的网站',
        preview: 'https://img.kuizuo.cn/js-de-obfuscator.png',
        website: 'https://deobfuscator.kuizuo.cn',
        source: 'https://github.com/kuizuo/js-de-obfuscator',
        tags: ['opensource', 'javascript'],
    },
    {
        title: '资源导航',
        description: '学习编程中遇到的资源整合网站',
        preview: 'https://img.kuizuo.cn/code-nav.png',
        website: 'https://nav.kuizuo.cn',
        source: 'https://github.com/kuizuo/code-nav',
        tags: ['opensource', 'javascript'],
    },
    {
        title: '愧怍在线工具',
        description: '基于React与MUI组件库编写的在线工具网站',
        preview: 'https://img.kuizuo.cn/tools.png',
        website: 'http://tools.kuizuo.cn',
        source: 'https://github.com/kuizuo/online-tools',
        tags: ['opensource', 'javascript'],
    },
];
exports.TagList = Object.keys(exports.Tags);
function sortProject() {
    let result = Projects;
    // Sort by site name
    // result = sortBy(result, (user) => user.title.toLowerCase());
    // Sort by favorite tag, favorites first
    // result = sortBy(result, (user) => !user.tags.includes('javascript'));
    return result;
}
exports.sortedProjects = sortProject();
