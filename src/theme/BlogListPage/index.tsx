import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import { HtmlClassNameProvider, ThemeClassNames } from '@docusaurus/theme-common'
import collection from '@site/src/css/collection.module.css'
import { useViewType } from '@site/src/hooks/useViewType'
import BackToTopButton from '@theme/BackToTopButton'
import type { Props } from '@theme/BlogListPage'
import BlogListPaginator from '@theme/BlogListPaginator'
import Layout from '@theme/Layout'
import SearchMetadata from '@theme/SearchMetadata'
import BlogPosts from './Posts'
import ViewTypeSwitch from './ViewTypeSwitch'
import styles from './styles.module.css'

export default function BlogListPage({ metadata, items }: Props): JSX.Element {
  const { viewType, toggleViewType } = useViewType()
  const title = translate({ id: 'theme.blog.title.new', message: '博客' })

  return (
    <HtmlClassNameProvider className={`${ThemeClassNames.wrapper.blogPages} ${ThemeClassNames.page.blogListPage}`}>
      <Layout title={metadata.blogTitle} description={metadata.blogDescription}>
        <SearchMetadata tag="blog_posts_list" />
        <main className={collection.page}>
          <div className={collection.container}>
            <header className={collection.header}>
              <div>
                <h1 className={collection.title}>{title}</h1>
                <p className={collection.description}><Translate id="blog.description">代码人生：编织技术与生活的博客之旅</Translate></p>
              </div>
              <div className={styles.headerLinks}>
                <Link to="/blog/tags" className={collection.textLink}>
                  <Translate id="blog.tags.browse">按标签浏览</Translate>
                  <span aria-hidden="true">→</span>
                </Link>
                <Link to="/blog/archive" className={collection.textLink}>
                  <Translate id="blog.archive">按年份浏览</Translate>
                  <span aria-hidden="true">→</span>
                </Link>
              </div>
            </header>
            <div className={styles.toolbar}>
              <p className={styles.results}>
                <Translate id="blog.count" values={{ count: metadata.totalCount }}>{'共 {count} 篇文章'}</Translate>
                {metadata.totalPages > 1 && <span><Translate id="blog.page" values={{ page: metadata.page, total: metadata.totalPages }}>{'第 {page} / {total} 页'}</Translate></span>}
              </p>
              <ViewTypeSwitch viewType={viewType} toggleViewType={toggleViewType} />
            </div>
            <div id="blog-posts">
              <BlogPosts items={items} viewType={viewType} />
            </div>
            <div className={styles.pagination}><BlogListPaginator metadata={metadata} /></div>
          </div>
        </main>
        <BackToTopButton />
      </Layout>
    </HtmlClassNameProvider>
  )
}
