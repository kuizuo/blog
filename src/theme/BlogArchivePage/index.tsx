import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import { HtmlClassNameProvider, ThemeClassNames, usePluralForm } from '@docusaurus/theme-common'
import useBrokenLinks from '@docusaurus/useBrokenLinks'
import collection from '@site/src/css/collection.module.css'
import type { ArchiveBlogPost, Props } from '@theme/BlogArchivePage'
import Layout from '@theme/Layout'
import styles from './styles.module.css'

type YearProps = {
  year: string
  posts: ArchiveBlogPost[]
}

function YearSection({ year, posts }: YearProps) {
  useBrokenLinks().collectAnchor(year)
  const { selectMessage } = usePluralForm()
  const count = selectMessage(posts.length, translate({
    id: 'theme.blog.archive.year.posts',
    message: '{count} 篇',
  }, { count: posts.length }))

  return (
    <section id={year} className={styles.yearSection} aria-labelledby={`year-heading-${year}`}>
      <div className={styles.yearHeader}>
        <h2 id={`year-heading-${year}`}>{year}</h2>
        <span>{count}</span>
      </div>
      <ul className={styles.postList}>
        {posts.map(post => (
          <li key={post.metadata.permalink}>
            <Link to={post.metadata.permalink} className={styles.postLink}>
              <time dateTime={post.metadata.date} className={styles.date}>
                {post.metadata.date.slice(5, 10)}
              </time>
              <span className={styles.postTitle}>{post.metadata.title}</span>
              <span className={styles.arrow} aria-hidden="true">→</span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  )
}

function listPostsByYears(blogPosts: readonly ArchiveBlogPost[]): YearProps[] {
  const postsByYear = new Map<string, ArchiveBlogPost[]>()
  for (const post of blogPosts) {
    const year = post.metadata.date.slice(0, 4)
    const posts = postsByYear.get(year) ?? []
    posts.push(post)
    postsByYear.set(year, posts)
  }
  return Array.from(postsByYear, ([year, posts]) => ({ year, posts }))
    .sort((left, right) => Number(right.year) - Number(left.year))
}

export default function BlogArchive({ archive }: Props) {
  const title = translate({
    id: 'theme.blog.archive.title',
    message: '历史博文',
    description: 'The page & hero title of the blog archive page',
  })
  const description = translate({
    id: 'theme.blog.archive.pageDescription',
    message: '按年份整理的文章，记录开发实践与生活。',
    description: 'The page description of the blog archive page',
  })
  const years = listPostsByYears(archive.blogPosts)

  return (
    <HtmlClassNameProvider className={`${ThemeClassNames.wrapper.blogPages} blog-archive-page`}>
      <Layout title={title} description={description}>
        <main className={collection.page}>
          <div className={collection.container}>
            <header className={collection.header}>
              <div>
                <h1 className={collection.title}>{title}</h1>
                <p className={collection.description}>
                  <Translate id="theme.blog.archive.posts.total" values={{ total: archive.blogPosts.length }}>
                    {'共 {total} 篇文章，记录一路上的探索与生活。'}
                  </Translate>
                </p>
              </div>
              <Link to="/blog" className={collection.textLink}>
                <Translate id="theme.blog.archive.allPosts">浏览全部文章</Translate>
                <span aria-hidden="true">→</span>
              </Link>
            </header>
            {years.length > 0 && (
              <div className={styles.archive}>
                <nav className={styles.yearNav} aria-label={translate({ id: 'theme.blog.archive.years', message: '按年份浏览' })}>
                  <p className={styles.navLabel}><Translate id="theme.blog.archive.years">按年份浏览</Translate></p>
                  <div className={styles.yearLinks}>
                    {years.map(({ year, posts }) => (
                      <Link
                        key={year}
                        to={`#${year}`}
                        aria-label={translate({ id: 'theme.blog.archive.year.link', message: '{year} 年，共 {count} 篇文章' }, { year, count: posts.length })}
                      >
                        {year}
                        <span aria-hidden="true">{posts.length}</span>
                      </Link>
                    ))}
                  </div>
                </nav>
                <div className={styles.years}>
                  {years.map(year => <YearSection key={year.year} {...year} />)}
                </div>
              </div>
            )}
          </div>
        </main>
      </Layout>
    </HtmlClassNameProvider>
  )
}
