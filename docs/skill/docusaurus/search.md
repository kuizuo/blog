---
id: docusaurus-search
slug: /docusaurus-search
title: 搜索
authors: kuizuo
---

[搜索 | Docusaurus](https://docusaurus.io/zh-CN/docs/search)

## algolia

有两种方式来配置algolia

一是让Docsearch 每周一次爬取你的网站，**前提是项目开源，否则收费**，好处是无需额外配置，申请比较繁琐，这个也是本博客目前采用的方式（推荐）

二是自己运行 DocSearch 爬虫，可以随时爬取，但需要自行去注册账号与搭建爬虫环境（docker）。

### 主动爬取

关于申请Algolia DocSearch在文档中有详细介绍，主要是要申请麻烦，需要等待邮箱，并且还需要回复内容给对方进行确认。所以免费托管的 DocSearch 条件是，比较苛刻的，但申请完几乎是一劳永逸，也是我非常推荐的。如果申请成功后就可以在[Crawler Admin Console](https://crawler.algolia.com/admin/crawlers) 中查看

![image-20220627232545640](https://img.kuizuo.cn/image-20220627232545640.png)

然后将得到algolia的appId，apiKey，indexName填写到docusaurus.config.js中即可。

```javascript title='docusaurus.config.js'
    algolia: {
      appId: 'GV6YN1ODMO',
      apiKey: '50303937b0e4630bec4a20a14e3b7872',
      indexName: 'kuizuo',
    }
```

### 手动爬取

[Run your own | DocSearch (algolia.com)](https://docsearch.algolia.com/docs/run-your-own)

这里我叙述下第二种方式的配置的过程，首先去申请 [Algolia](https://www.algolia.com/) 账号，然后在左侧 indices 创建索引，在 API Keys 中获取 Application ID 和 API Key（注意，有两个 API KEY）

![image-20210821230135749](https://img.kuizuo.cn/image-20210821230135749.png)

![image-20210821230232837](https://img.kuizuo.cn/image-20210821230232837.png)

填入到`docusaurus.config.js`中的 API KEY 是 **Search-Only API Key**

```js
themeConfig: {
    algolia: {
      apiKey: "xxxxxxxxxxx",
      appId: "xxxxxxxxxxx",
      indexName: "kuizuo",
    },
}
```

系统我选用的是 Linux，在 Docker 的环境下运行爬虫代码。不过要先 [安装 jq ](https://github.com/stedolan/jq/wiki/Installation#zero-install) 我这里选择的是 0install 进行安装（安装可能稍慢），具体可以查看文档，然后在控制台查看安装结果

```
[root@kzserver kuizuo.cn]# jq --version
jq-1.6
```

接着在任意目录中创建`.env`文件，填入对应的 APPID 和 API KEY（这里是`Admin API Key`，当时我还一直以为是 Search API Key 坑了我半天😭）

```js
APPLICATION_ID = YOUR_APP_ID
API_KEY = YOUR_API_KEY
```

然后创建`docsearch.json`文件，然后填入对应的配置代码，这里贴下配置[docsearch-configs/docsearch.json](https://github.com/algolia/docsearch-configs/blob/master/configs/docsearch.json)

更改索引名与网站名

```json title="docsearch.json"
{
  "index_name": "kuizuo",
  "start_urls": [
    "https://kuizuo.cn/"
  ],
  "sitemap_urls": [
    "https://kuizuo.cn/sitemap.xml"
  ],
  ...
}
```

运行 docker 命令

```sh
docker run -it --env-file=.env -e "CONFIG=$(cat docsearch.json | jq -r tostring)" algolia/docsearch-scraper
```

接着等待容器运行，爬取你的网站即可。最终打开 algolia 控制台提示如下页面则表示成功

![image-20210821225934002](https://img.kuizuo.cn/image-20210821225934002.png)

不过还是建议使用去申请Docsearch，其每周自动爬取站点，而不是手动爬取。

## 本地搜索

如果你嫌algolia申请比较麻烦，docusaurus也提供本地搜索，不过搜索上肯定会比全文搜索来的差一些。

本地搜索插件：[docusaurus-search-local](https://github.com/cmfcmf/docusaurus-search-local)
