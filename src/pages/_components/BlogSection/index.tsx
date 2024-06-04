import Link from '@docusaurus/Link'
import Translate from '@docusaurus/Translate'
import type { BlogPost } from '@docusaurus/plugin-content-blog'
import { usePluginData } from '@docusaurus/useGlobalData'
import { cn } from '@site/src/lib/utils'
import Image from '@theme/IdealImage'
import { motion, useScroll, useTransform } from 'framer-motion'
import React from 'react'

import SectionTitle from '../SectionTitle'
import styles from './styles.module.css'

const chunk = (arr, size) =>
  Array.from({ length: Math.ceil(arr.length / size) }, (_, i) => arr.slice(i * size, i * size + size))

const BLOG_POSTS_COUNT = 6
const BLOG_POSTS_PER_ROW = 2

export function BlogItem({ post }: { post: BlogPost }) {
  const {
    metadata: { permalink, frontMatter, title, description },
  } = post

  return (
    <motion.li
      className={cn('card', 'margin-bottom--md')}
      key={permalink}
      initial={{ y: 100, opacity: 0.001 }}
      whileInView={{ y: 0, opacity: 1, transition: { duration: 0.5 } }}
      whileHover={{ y: -10, transition: { duration: 0.3 } }}
      viewport={{ once: true }}
    >
      {frontMatter.image && (
        <Link href={permalink} className={styles.image}>
          <Image src={frontMatter?.image} alt={title} img={''} />
        </Link>
      )}
      <div className={'card__body'}>
        <h4>
          <Link href={permalink}>{title}</Link>
        </h4>
        <p>{description}</p>
      </div>
    </motion.li>
  )
}

export default function BlogSection(): JSX.Element {
  const blogData = usePluginData('docusaurus-plugin-content-blog') as {
    posts: BlogPost[]
    postNum: number
    tagNum: number
  }

  const posts = chunk(blogData.posts.slice(0, BLOG_POSTS_COUNT), BLOG_POSTS_PER_ROW)

  const ref = React.useRef<HTMLDivElement>(null)

  const { scrollYProgress } = useScroll()
  const y = useTransform(scrollYProgress, [0, 0.5, 1], [20, 0, -20], {
    clamp: false,
  })

  if (blogData.postNum === 0) {
    return <>作者还没开始写博文哦...</>
  }

  return (
    <section className={cn('padding-vert--sm container', 'max-w-7xl')}>
      <SectionTitle icon="ri:quill-pen-line" href={'/blog'}>
        <Translate id="homepage.blog.title">近期博客</Translate>
      </SectionTitle>
      <div ref={ref} className={cn('row', styles.list)}>
        {posts.map((postGroup, index) => (
          <div className="col margin-top--sm col-6" key={index}>
            {postGroup.map((post, i) => (
              <motion.div style={{ y: i / 2 ? y : 0 }} key={i}>
                <BlogItem key={post.id} post={post} />
              </motion.div>
            ))}
          </div>
        ))}
      </div>
    </section>
  )
}
