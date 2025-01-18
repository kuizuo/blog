import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import { HtmlClassNameProvider, PageMetadata, ThemeClassNames } from '@docusaurus/theme-common'
import { Icon } from '@iconify/react'
import { cn } from '@site/src/lib/utils'
import type { ArchiveBlogPost, Props } from '@theme/BlogArchivePage'
import styles from './styles.module.css'

import { type Variants, motion } from 'framer-motion'

import MyLayout from '../MyLayout'

type YearProp = {
  year: string
  posts: ArchiveBlogPost[]
}

const variants: Variants = {
  from: { opacity: 0.01, y: 50 },
  to: i => ({
    opacity: 1,
    y: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 100,
      bounce: 0.2,
      duration: 0.3,
      delay: i * 0.1,
    },
  }),
}

const formatDate = (dateString) => {
  const date = new Date(dateString)
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')

  return `${month}-${day}`
}

function Year({ posts }: YearProp) {
  return (
    <>
      <ul className={styles.archiveList}>
        {posts.map((post, i) => (
          <motion.li
            key={post.metadata.permalink}
            className={styles.archiveItem}
            custom={i}
            initial="from"
            animate="to"
            variants={variants}
            viewport={{ once: true, amount: 0.8 }}
          >
            <Link to={post.metadata.permalink}>
              <time className={styles.archiveTime}>{formatDate(post.metadata.date)}</time>
              <span>{post.metadata.title}</span>
            </Link>
          </motion.li>
        ))}
      </ul>
    </>
  )
}

function YearsSection({ years }: { years: YearProp[] }) {
  return (
    <div className="margin-top--md">
      {years.map((_props, idx) => (
        <motion.div key={idx} initial="from" animate="to" custom={idx} variants={variants}>
          <div className={styles.archiveYear}>
            <h3 className={styles.archiveYearTitle}>{_props.year}</h3>
            <span>
              <i>
                {(years[idx] as YearProp).posts.length}
                {' '}
              </i>
              <Translate id="theme.blog.archive.posts.unit">篇</Translate>
            </span>
          </div>
          <Year {..._props} />
        </motion.div>
      ))}
    </div>
  )
}

function listPostsByYears(blogPosts: readonly ArchiveBlogPost[]): YearProp[] {
  const postsByYear = blogPosts.reduceRight((posts, post) => {
    const year = post.metadata.date.split('-')[0]!
    const yearPosts = posts.get(year) ?? []
    return posts.set(year, [post, ...yearPosts])
  }, new Map<string, ArchiveBlogPost[]>())

  return Array.from(postsByYear, ([year, posts]) => ({
    year,
    posts,
  })).reverse()
}

export default function BlogArchive({ archive }: Props) {
  const title = translate({
    id: 'theme.blog.archive.title',
    message: 'Archive',
    description: 'The page & hero title of the blog archive page',
  })
  const description = translate({
    id: 'theme.blog.archive.description',
    message: 'Archive',
    description: 'The page & hero description of the blog archive page',
  })

  const years = listPostsByYears(archive.blogPosts)
  return (
    <HtmlClassNameProvider className={cn(ThemeClassNames.wrapper.blogPages, ThemeClassNames.page.blogTagsListPage)}>
      <PageMetadata title={title} description={description} />
      <MyLayout>
        <h2 className={styles.archiveTitle}>
          <Icon icon="carbon:blog" width={24} height={24} />
          {title}
        </h2>
        <p>
          <Translate id="theme.blog.archive.posts.total" values={{ total: archive.blogPosts.length }}>
            {'当前共有 {total} 篇文章，请持续保持创作！'}
          </Translate>
        </p>
        {years.length > 0 && <YearsSection years={years} />}
      </MyLayout>
    </HtmlClassNameProvider>
  )
}
