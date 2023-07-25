import React from 'react'
import Link from '@docusaurus/Link'
import type { Props as BlogPostItemsProps } from '@theme/BlogPostItems'

import styles from './styles.module.scss'

export default function BlogPostGridItems({
  items,
}: BlogPostItemsProps): JSX.Element {
  return (
    <>
      {items.map(({ content: BlogPostContent }) => {
        const { metadata: blogMetaData, frontMatter } = BlogPostContent
        const { title } = frontMatter
        const { permalink, date, tags } = blogMetaData
        const dateObj = new Date(date)
        const dateString = `${dateObj.getFullYear()}-${(
          '0' +
          (dateObj.getMonth() + 1)
        ).slice(-2)}-${('0' + dateObj.getDate()).slice(-2)}`

        return (
          <div className={styles.postGridItem} key={blogMetaData.permalink}>
            <Link to={permalink} className={styles.itemTitle}>
              {title}
            </Link>
            <div className={styles.itemTags}>
              {tags.length > 0 &&
                tags
                  .slice(0, 2)
                  .map(({ label, permalink: tagPermalink }, index) => (
                    <Link
                      key={tagPermalink}
                      className={`post__tags ${
                        index < tags.length ? 'margin-right--sm' : ''
                      }`}
                      to={tagPermalink}
                      style={{ fontSize: '0.75em', fontWeight: 500 }}
                    >
                      {label}
                    </Link>
                  ))}
            </div>
            <div className={styles.itemDate}>{dateString}</div>
          </div>
        )
      })}
    </>
  )
}
