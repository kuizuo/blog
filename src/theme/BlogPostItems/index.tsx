import React from 'react'
import { BlogPostProvider } from '@docusaurus/theme-common/internal'
import BlogPostItem from '@theme/BlogPostItem'
import type { Props } from '@theme/BlogPostItems'

import { motion, Variants } from 'framer-motion'

const cardVariants: Variants = {
  from: {
    y: 50,
  },
  to: {
    y: 0,
    transition: {
      type: 'spring',
      bounce: 0.2,
      duration: 0.8,
    },
  },
}

export default function BlogPostItems({
  items,
  component: BlogPostItemComponent = BlogPostItem,
}: Props): JSX.Element {
  return (
    <>
      {items.map(({ content: BlogPostContent }) => (
        <BlogPostProvider
          key={BlogPostContent.metadata.permalink}
          content={BlogPostContent}
        >
          <motion.div
            initial="from"
            whileInView="to"
            viewport={{ once: true, amount: 0.8 }}
            variants={cardVariants}
          >
            <BlogPostItemComponent>
              <BlogPostContent />
            </BlogPostItemComponent>
          </motion.div>
        </BlogPostProvider>
      ))}
    </>
  )
}
