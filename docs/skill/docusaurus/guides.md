---
id: docusaurus-guides
title: Docusaurus2 主题魔改
authors: kuizuo
keywords: ['guides', 'docusaurus', 'docusaurus-guides']
---

这里是本人对[Docusaurus](https://docusaurus.io/)的魔改指南，帮助使用者更好使用 Docusaurus。

同时 [Docusaurus 2.0](https://docusaurus.io/zh-CN/blog/2022/08/01/announcing-docusaurus-2.0) 也正式发布了，顺带升级依赖与重构项目使其易懂易用。

import DocCardList from '@theme/DocCardList'; import {useCurrentSidebarCategory} from '@docusaurus/theme-common';

<DocCardList items={useCurrentSidebarCategory().items}/>
