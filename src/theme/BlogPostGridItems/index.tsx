import React from 'react'
import { Variants, motion } from 'framer-motion'
import Link from '@docusaurus/Link'
import type { Props as BlogPostItemsProps } from '@theme/BlogPostItems'
import Tag from '@theme/Tag'

import styles from './styles.module.scss'

const variants: Variants = {
  from: { opacity: 0.01, y: 20 },
  to: i => ({
    opacity: 1,
    y: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 100,
      bounce: 0.3,
      duration: 0.3,
      delay: i * 0.1,
    },
  }),
}

export default function BlogPostGridItems({
  items,
}: BlogPostItemsProps): JSX.Element {
  return (
    <>
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
            initial="from"
            animate="to"
            custom={i / 2}
            viewport={{ once: true, amount: 0.8 }}
            variants={variants}
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
                      className={styles.tag}
                    />
                  ))}
            </div>
            <div className={styles.itemDate}>{dateString}</div>
          </motion.div>
        )
      })}
    </>
  )
}
