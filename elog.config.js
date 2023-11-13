module.exports = {
    write: {
        platform: 'yuque',
        yuque: {
            token: process.env.YUQUE_TOKEN,
            login: process.env.YUQUE_LOGIN,
            repo: process.env.YUQUE_REPO,
            onlyPublic: false,
            onlyPublished: true,
        },
        'yuque-pwd': {
            username: process.env.YUQUE_USERNAME,
            password: process.env.YUQUE_PASSWORD,
            login: process.env.YUQUE_LOGIN,
            repo: process.env.YUQUE_REPO,
            onlyPublic: false,
            onlyPublished: true,
            linebreak: false,
        },
        notion: {
            token: process.env.NOTION_TOKEN,
            databaseId: process.env.NOTION_DATABASE_ID,
            filter: false, // {property: 'status', select: {equals: '已发布'}}
            sorts: false, // [{timestamp: 'created_time', direction: 'descending'}],
            catalog: false,
        },
        feishu: {
            type: 'space',
            wikiId: process.env.FEISHU_WIKI_ID,
            folderToken: process.env.FEISHU_FOLDER_TOKEN,
            appId: process.env.FEISHU_APP_ID,
            appSecret: process.env.FEISHU_APP_SECRET,
        },
        flowus: {
            tablePageId: process.env.FLOWUS_TABLE_PAGE_ID,
            filter: false, // {property: 'status',value: '已发布'}
            sort: false, // { property: 'createdAt', direction: 'descending' }
            catalog: false,
        },
    },
    deploy: {
        platform: 'local',
        local: {
            outputDir: './docs',
            filename: 'title',
            format: 'markdown',
            catalog: true,
            formatExt: '',
        },
        confluence: {
            user: process.env.CONFLUENCE_USER,
            password: process.env.WORDPRESS_PASSWORD,
            endpoint: process.env.WORDPRESS_ENDPOINT,
            spaceKey: process.env.CONFLUENCE_SPACE_KEY,
            rootPageId: process.env.CONFLUENCE_ROOT_PAGE_ID, // 可选
            formatExt: '', // 可选
        },
        wordpress: {
            username: process.env.WORDPRESS_USERNAME,
            password: process.env.WORDPRESS_PASSWORD,
            endpoint: process.env.WORDPRESS_ENDPOINT,
            keyMap: {
                tags: 'tags',
                categories: 'categories',
                cover: 'cover',
                description: 'description',
            },
            formatExt: ''
        },
    },
    image: {
        enable: true,
        platform: 'local',
        local: {
            // outputDir: './docs/images',
            outputDir: './static/img/others',
            prefixKey: '/img/others',
            pathFollowDoc: false,
            imagePathExt: '',
        },
        oss: {
            secretId: process.env.OSS_SECRET_ID,
            secretKey: process.env.OSS_SECRET_KEY,
            bucket: process.env.OSS_BUCKET,
            region: process.env.OSS_REGION,
            host: process.env.OSS_HOST,
            prefixKey: '',
            secretExt: '', // 可选
        },
        cos: {
            secretId: process.env.COS_SECRET_ID,
            secretKey: process.env.COS_SECRET_KEY,
            bucket: process.env.COS_BUCKET,
            region: process.env.COS_REGION,
            host: process.env.COS_HOST,
            prefixKey: '',
            secretExt: '', // 可选
        },
        qiniu: {
            secretId: process.env.QINIU_SECRET_ID,
            secretKey: process.env.QINIU_SECRET_KEY,
            bucket: process.env.QINIU_BUCKET,
            region: process.env.QINIU_REGION,
            host: process.env.QINIU_HOST,
            prefixKey: '',
            secretExt: '', // 可选
        },
        upyun: {
            user: process.env.UPYUN_USER,
            password: process.env.UPYUN_PASSWORD,
            bucket: process.env.UPYUN_BUCKET,
            host: process.env.UPYUN_HOST,
            prefixKey: '',
            secretExt: '', // 可选
        },
        github: {
            user: process.env.GITHUB_USER,
            token: process.env.GITHUB_TOKEN,
            repo: process.env.GITHUB_REPO,
            branch: '',
            host: '',
            prefixKey: '',
            secretExt: '', // 可选
        },
    },
}
