import React, { useEffect } from 'react'
import clsx from 'clsx'
import {
  motion,
  useMotionValue,
  useMotionValueEvent,
  useScroll,
  useSpring,
  useTransform,
  useVelocity,
} from 'framer-motion'
import type { BlogPost } from '@site/src/plugin/plugin-content-blog/src/types'
import useGlobalData from '@docusaurus/useGlobalData'
import Translate from '@docusaurus/Translate'
import Link from '@docusaurus/Link'
import Image from '@theme/IdealImage'

import { useWindowSize } from '@site/src/hooks/useWindowSize'

import styles from './styles.module.scss'

const chunk = (arr, size) =>
  Array.from({ length: Math.ceil(arr.length / size) }, (_, i) =>
    arr.slice(i * size, i * size + size),
  )

export function BlogItem({ post }: { post: BlogPost }) {
  const {
    metadata: { permalink, frontMatter, title, description },
  } = post

  return (
    <>
      <motion.li
        className={clsx('card', 'margin-bottom--md')}
        key={permalink}
        initial={{ y: 50, opacity: 0 }}
        whileInView={{ y: 0, opacity: 1, transition: { duration: 0.3 } }}
        whileHover={{ y: -10, transition: { duration: 0.3 } }}
        viewport={{ once: true }}
      >
        {frontMatter.image && (
          <Link href={permalink} className={styles.image}>
            <Image src={frontMatter.image!} alt={title} img={''} />
          </Link>
        )}
        <div className={'card__body'}>
          <h4>
            <Link href={permalink}>{title}</Link>
          </h4>
          <p>{description}</p>
        </div>
      </motion.li>
    </>
  )
}

export default function BlogRecent(): JSX.Element {
  const { width } = useWindowSize()

  const globalData = useGlobalData()
  const blogPluginData = globalData?.['docusaurus-plugin-content-blog']?.[
    'default'
  ] as any

  const blogData = blogPluginData?.blogs as BlogPost[]
  const posts = chunk(blogData.slice(0, 6), 2)

  const ref = React.useRef<HTMLDivElement>(null)

  const { scrollYProgress } = useScroll()
  const y = useTransform(scrollYProgress, [0, 0.5, 1], [20, 0, -10], {
    clamp: false,
  })

  if (blogData.length === 0) {
    return <>作者还没有写过博客哦</>
  }

  return (
    <>
      <div
        className={clsx(
          'container padding-vert--sm margin-vert--md',
          styles.blogContainer,
        )}
      >
        <h2 style={{ textAlign: 'center' }}>
          <Translate id="theme.blog.title.recommend">近期博客</Translate>
        </h2>
        <div ref={ref} className={clsx('row', styles.list)}>
          {posts.map((postGroup, index) => (
            <div className="col col-6" key={index}>
              {postGroup.map((post, i) =>
                width < 998 ? (
                  <BlogItem key={post.id} post={post} />
                ) : (
                  <motion.div style={{ y: i / 2 ? y : 0 }}>
                    <BlogItem key={post.id} post={post} />
                  </motion.div>
                ),
              )}
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
