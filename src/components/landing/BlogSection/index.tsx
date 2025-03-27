import Link from '@docusaurus/Link'
import Translate from '@docusaurus/Translate'
import type { BlogPost } from '@docusaurus/plugin-content-blog'
import { usePluginData } from '@docusaurus/useGlobalData'
import { cn } from '@site/src/lib/utils'
import Image from '@theme/IdealImage'
import { motion, useScroll, useTransform } from 'framer-motion'
import React from 'react'
import { Section } from '../Section'

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
      className={cn('card', 'margin-bottom--md flex w-full bg-blog shadow-blog')}
      key={permalink}
      initial={{ y: 100, opacity: 0.001 }}
      whileInView={{ y: 0, opacity: 1, transition: { duration: 0.5 } }}
      whileHover={{ y: -10, transition: { duration: 0.3 } }}
      viewport={{ once: true }}
    >
      {frontMatter.image && (
        <Link href={permalink} className="max-h-[240px] w-full cursor-pointer overflow-hidden object-cover">
          <Image src={frontMatter?.image} alt={title} img="" />
        </Link>
      )}
      <div className="card__body">
        <h4 className="text-base">
          <Link href={permalink} className="relative hover:no-underline">
            {title}
          </Link>
        </h4>
        <p className="text-sm">{description}</p>
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
    return <>O autor ainda não começou a escrever...</>
  }

  return (
    <Section title={<Translate id="homepage.blog.title">Posts recentes</Translate>} icon="ri:quill-pen-line" href="/blog">
      <div ref={ref} className="flex flex-col gap-4 overflow-hidden rounded-card p-3 md:grid md:grid-cols-12">
        {posts.map((postGroup, index) => (
          <div className="col-span-4" key={index}>
            {postGroup.map((post, i) => (
              <motion.div style={{ y: i / 2 ? y : 0 }} key={i}>
                <BlogItem key={post.id} post={post} />
              </motion.div>
            ))}
          </div>
        ))}
      </div>
    </Section>
  )
}
