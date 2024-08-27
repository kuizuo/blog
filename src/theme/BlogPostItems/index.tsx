import { BlogPostProvider } from '@docusaurus/plugin-content-blog/client'
import BlogPostItem from '@theme/BlogPostItem'
import type { Props } from '@theme/BlogPostItems'
import { type Variants, motion } from 'framer-motion'

const variants: Variants = {
  from: { opacity: 0.001, y: 100 },
  to: i => ({
    opacity: 1,
    y: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 100,
      bounce: 0.2,
      duration: 0.3,
      delay: i * 0.2,
    },
  }),
}

export default function BlogPostItems({ items, component: BlogPostItemComponent = BlogPostItem }: Props): JSX.Element {
  return (
    <>
      {items.map(({ content: BlogPostContent }, i) => (
        <BlogPostProvider key={BlogPostContent.metadata.permalink} content={BlogPostContent}>
          <motion.div initial="from" animate="to" custom={i} viewport={{ once: true, amount: 0.8 }} variants={variants}>
            <BlogPostItemComponent>
              <BlogPostContent />
            </BlogPostItemComponent>
          </motion.div>
        </BlogPostProvider>
      ))}
    </>
  )
}
