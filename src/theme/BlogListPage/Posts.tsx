import Link from '@docusaurus/Link'
import Translate from '@docusaurus/Translate'
import type { PropBlogPostContent } from '@docusaurus/plugin-content-blog'
import type { ViewType } from '@site/src/hooks/useViewType'
import type { Props } from '@theme/BlogPostItems'
import { motion, useReducedMotion } from 'motion/react'
import { useState } from 'react'
import { ReadingTime } from '../BlogPostItem/Header/Info'
import styles from './posts.module.css'

function Post({ content, viewType }: { content: PropBlogPostContent, viewType: ViewType }) {
  const { metadata, assets } = content
  const { title, date, permalink, description, readingTime, tags, frontMatter } = metadata
  const [imageFailed, setImageFailed] = useState(false)
  const reduceMotion = useReducedMotion()
  const image = frontMatter.hideImage === true || imageFailed ? undefined : assets.image ?? frontMatter.image

  return (
    <motion.article
      className={styles.post}
      data-cover={Boolean(image)}
      layout={reduceMotion ? false : 'position'}
      layoutDependency={viewType}
      transition={{ layout: { duration: 0.28, ease: [0.16, 1, 0.3, 1] } }}
    >
      <div className={styles.body}>
        <div className={styles.meta}>
          <time dateTime={date}>{date.slice(0, 10)}</time>
          {typeof readingTime === 'number' && <span><ReadingTime readingTime={readingTime} /></span>}
          {Boolean(frontMatter.sticky) && <span className={styles.pinned}><Translate id="blog.post.pinned">置顶</Translate></span>}
        </div>
        <h2 className={styles.title}>
          <Link to={permalink} className={styles.titleLink}>{title}</Link>
        </h2>
        {description && <p className={styles.summary}>{description}</p>}
        {tags.length > 0 && (
          <ul className={styles.tags}>
            {tags.slice(0, 3).map(tag => (
              <li key={tag.permalink}><Link to={tag.permalink}>{tag.label}</Link></li>
            ))}
          </ul>
        )}
      </div>
      {image && (
        <div className={styles.cover} aria-hidden="true">
          <img src={image} alt="" loading="lazy" decoding="async" onError={() => setImageFailed(true)} />
        </div>
      )}
    </motion.article>
  )
}

export default function BlogPosts({ items, viewType }: Props & { viewType: ViewType }) {
  return (
    <div className={styles.posts} data-view={viewType}>
      {items.map(({ content }) => <Post key={content.metadata.permalink} content={content} viewType={viewType} />)}
    </div>
  )
}
