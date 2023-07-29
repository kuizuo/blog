import React from 'react'
import { Variants, motion } from 'framer-motion'
import Link from '@docusaurus/Link'
import type { Props as BlogPostItemsProps } from '@theme/BlogPostItems'
import Tag from '@theme/Tag'

import styles from './styles.module.scss'

const container = {
  hidden: { opacity: 1, scale: 0 },
  visible: {
    opacity: 1,
    scale: 1,
    transition: {
      delayChildren: 0.3,
      staggerChildren: 0.2,
    },
  },
}

const item = {
  hidden: { y: 20, opacity: 0 },
  visible: {
    y: 0,
    opacity: 1,
  },
}

export default function BlogPostGridItems({
  items,
}: BlogPostItemsProps): JSX.Element {
  return (
    <motion.div
      className={styles.blogGrid}
      variants={container}
      initial="hidden"
      animate="visible"
    >
      {items.map(({ content: BlogPostContent }, i) => {
        const { metadata: blogMetaData, frontMatter } = BlogPostContent
        const { title } = frontMatter
        const { permalink, date, tags } = blogMetaData
        const dateObj = new Date(date)
        const dateString = `${dateObj.getFullYear()}-${(
          '0' +
          (dateObj.getMonth() + 1)
        ).slice(-2)}-${('0' + dateObj.getDate()).slice(-2)}`

        return (
          <motion.div
            className={styles.postGridItem}
            key={blogMetaData.permalink}
            variants={item}
          >
            <Link to={permalink} className={styles.itemTitle}>
              {title}
            </Link>
            <div className={styles.itemTags}>
              {tags.length > 0 &&
                tags
                  .slice(0, 2)
                  .map(({ label, permalink: tagPermalink }, index) => (
                    <Tag
                      label={label}
                      permalink={tagPermalink}
                      key={tagPermalink}
                      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                      // @ts-ignore
                      className={styles.tag}
                    />
                  ))}
            </div>
            <div className={styles.itemDate}>{dateString}</div>
          </motion.div>
        )
      })}
    </motion.div>
  )
}
