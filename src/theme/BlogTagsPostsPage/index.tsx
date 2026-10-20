import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import { HtmlClassNameProvider, ThemeClassNames } from '@docusaurus/theme-common'
import { useBlogTagsPostsPageTitle } from '@docusaurus/theme-common/internal'
import collection from '@site/src/css/collection.module.css'
import { useViewType } from '@site/src/hooks/useViewType'
import BackToTopButton from '@theme/BackToTopButton'
import BlogListPaginator from '@theme/BlogListPaginator'
import type { Props } from '@theme/BlogTagsPostsPage'
import Unlisted from '@theme/ContentVisibility/Unlisted'
import Layout from '@theme/Layout'
import SearchMetadata from '@theme/SearchMetadata'
import BlogPosts from '../BlogListPage/Posts'
import ViewTypeSwitch from '../BlogListPage/ViewTypeSwitch'
import blogStyles from '../BlogListPage/styles.module.css'
import styles from './styles.module.css'

export default function BlogTagsPostsPage({ tag, items, listMetadata }: Props): JSX.Element {
  const title = useBlogTagsPostsPageTitle(tag)
  const description = tag.description || translate({ id: 'blog.tags.posts.description', message: '阅读与「{tag}」有关的文章。' }, { tag: tag.label })
  const { viewType, toggleViewType } = useViewType()

  return (
    <HtmlClassNameProvider className={`${ThemeClassNames.wrapper.blogPages} ${ThemeClassNames.page.blogTagPostListPage}`}>
      <Layout title={title} description={description}>
        <SearchMetadata tag="blog_tags_posts" />
        <main className={collection.page}>
          <div className={collection.container}>
            {tag.unlisted && <Unlisted />}
            <header className={collection.header}>
              <div className={styles.heading}>
                <h1 className={`${collection.title} ${styles.title}`}>
                  <span className={styles.hash} aria-hidden="true">#</span>
                  {tag.label}
                </h1>
                <p className={collection.description}>{description}</p>
              </div>
              <Link to={tag.allTagsPath} className={collection.textLink}>
                <span aria-hidden="true">←</span>
                <Translate id="blog.tags.all">全部标签</Translate>
              </Link>
            </header>
            <div className={blogStyles.toolbar}>
              <p className={blogStyles.results}>
                <Translate id="blog.count" values={{ count: tag.count }}>{'共 {count} 篇文章'}</Translate>
                {listMetadata.totalPages > 1 && <span><Translate id="blog.page" values={{ page: listMetadata.page, total: listMetadata.totalPages }}>{'第 {page} / {total} 页'}</Translate></span>}
              </p>
              <ViewTypeSwitch viewType={viewType} toggleViewType={toggleViewType} />
            </div>
            <div id="blog-posts"><BlogPosts items={items} viewType={viewType} /></div>
            <div className={blogStyles.pagination}><BlogListPaginator metadata={listMetadata} /></div>
          </div>
        </main>
        <BackToTopButton />
      </Layout>
    </HtmlClassNameProvider>
  )
}
