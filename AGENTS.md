# AGENTS.md

本文件是给 Codex 和其他编码代理看的项目说明。优先遵守离当前工作目录最近的 `AGENTS.md`；如果没有更近的说明，就遵守本文件。

## 项目概览

这是愧怍的个人博客项目，基于 Docusaurus 3、React、TypeScript 和 TailwindCSS 构建，主要内容是博客文章、Docusaurus 主题魔改文档、项目展示、友链和个人资料页。

主要目录：

- `blog/`：博客文章，按主题分为 `annual`、`develop`、`lifestyle`、`program`、`project`、`reference` 等目录。
- `docs/`：文档内容，目前主要是 Docusaurus 主题魔改相关说明，侧边栏配置在 `sidebars.ts`。
- `data/`：首页、项目页、友链、技能、社交链接等结构化数据。
- `src/pages/`：自定义页面，例如首页、项目页、友链页、关于页。
- `src/components/`：项目组件，包括首页区块、评论、浏览器窗口、动效组件等。
- `src/theme/`：Docusaurus 主题覆盖组件，修改时要谨慎，优先保持 Docusaurus 原有行为。
- `src/plugin/plugin-content-blog/`：自定义博客内容插件，用于改写 Docusaurus 博客数据能力。
- `src/css/`：全局样式和主题样式。
- `static/`：静态资源，图片路径通常以 `/img/...`、`/svg/...` 方式引用。
- `i18n/`：翻译资源。当前站点配置默认语言是 `zh-CN`。
- `skill/kuizuo/`：本地 Codex Skill 资料，不是站点常规业务代码；只有明确要求时再修改。

不要编辑 `node_modules/`、`.docusaurus/`、`build/` 这类依赖或生成产物。

## 运行环境和命令

使用 pnpm，仓库声明的包管理器是 `pnpm@9.15.4`。`package.json` 里声明 Node 版本为 `>=24.0`，CI 也应保持 Node 24 或更高版本。

常用命令：

- 安装依赖：`pnpm install`
- 本地开发：`pnpm dev`
- 构建站点：`pnpm build`
- 构建后预览：`pnpm serve`
- 代码检查：`pnpm lint`
- 自动修复部分检查问题：`pnpm lint:fix`
- 清理缓存和生成目录：`pnpm clear`
- 写入标题 ID：`pnpm write-heading-ids`
- 写入翻译文件：`pnpm write-translations`

`pnpm index` 会通过 Docker、`.env`、`jq` 和 `docsearch.json` 运行 Algolia DocSearch 抓取，不要在没有明确需求和环境确认时随意运行。

## 编码约定

- TypeScript 配置是严格模式。新增代码要尽量保留类型信息，不要为了省事扩大 `any` 的使用范围。
- 跟随现有代码风格：两个空格缩进、单引号、通常不写分号。
- React 组件优先使用函数组件，优先复用已有组件、Hook 和工具函数。
- 局部样式优先使用同目录 `styles.module.css`；已有组件使用 Tailwind 时再沿用 Tailwind。不要引入新的样式体系。
- Docusaurus 页面和主题组件优先使用 Docusaurus 提供的 API、主题别名和布局能力。
- 修改 `src/theme/` 时，把它当作 Docusaurus 主题覆盖层处理：保持原主题的可访问性、路由、SEO、代码块、博客分页和归档等行为。
- 修改 `src/plugin/plugin-content-blog/` 时，要关注博客列表、归档、标签、RSS、阅读时间、编辑链接等下游行为。
- 除非任务明确要求，不要新增依赖；确实需要新增依赖时，同时更新 `package.json` 和 `pnpm-lock.yaml`。

## 内容写作约定

- 博客和文档通常使用 Markdown 或 MDX，保留现有中文表达风格，不要把个人化文字改成通用说明文。
- 新增博客文章时，参考现有文章的 front matter，常见字段包括 `slug`、`title`、`date`、`authors`、`tags`、`keywords`、`image`、`description`。
- 博客列表截断使用 `{/* truncate */}`，需要列表页摘要时要保留或添加。
- 本地静态图片放在 `static/` 下，引用时使用站点根路径，例如 `/img/project/blog.png`。
- 外链图片已有大量使用 `https://img.kuizuo.me/...`，新增时保持路径清晰、说明文字准确。
- 如果改导航、页脚、页面标题、按钮文案等可见文字，要同步检查 `i18n/` 下是否需要更新。

## 验证要求

交付前尽量实际验证，不要只改文件就结束。

- 只改文案、文章或配置较少时，至少回读改动文件，确认路径、字段、链接和格式正确。
- 改 TypeScript、React、主题组件、插件或数据文件后，运行 `pnpm lint`。
- 改路由、Docusaurus 配置、博客插件、MDX、静态资源或会影响页面生成的内容后，运行 `pnpm build`。
- 改可视化页面或交互后，启动 `pnpm dev`，在浏览器里检查相关页面；如果影响范围不确定，至少检查 `/`、`/blog`、`/project`、`/friends`、`/about`。
- 本项目当前没有独立测试脚本，不要声称已经跑过测试；用实际执行过的 lint、build 或浏览器检查来说明结果。
- 如果某个命令因为环境问题无法运行，要记录具体原因，并尽量用次优方式验证。

## 协作和交付

- 开始复杂任务前先明确完成标准：做到什么程度算完成、需要验证哪些页面或命令。
- 先读项目现有实现，再动手；不要用通用模板覆盖这个仓库已有模式。
- 保持改动范围小。不要顺手重构无关文件，不要修改生成产物。
- 如果工作树里有别人已有改动，不要回退；只处理本次任务需要的文件。
- 最终汇报用简单直白的中文说明做了什么、结果怎样、验证了什么。避免堆术语和实现细节。
