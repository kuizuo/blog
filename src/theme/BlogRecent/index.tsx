import React from 'react'
import clsx from 'clsx'
import { motion } from 'framer-motion'
import type { BlogPost } from '@site/src/plugin/plugin-content-blog/src/types'
import useGlobalData from '@docusaurus/useGlobalData'
import Translate from '@docusaurus/Translate'
import Link from '@docusaurus/Link'
import Image from '@theme/IdealImage'

import styles from './styles.module.scss'

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
        whileInView={{ y: 0, opacity: 1 }}
        transition={{ duration: 1 }}
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
  const globalData = useGlobalData()
  const blogPluginData = globalData?.['docusaurus-plugin-content-blog']?.[
    'default'
  ] as any

  const blogData = blogPluginData?.blogs as BlogPost[]
  const recentPosts = blogData.slice(0, 6)

  const chunk = (arr: any[], size: number) =>
    Array.from({ length: Math.ceil(arr.length / size) }, (v, i) =>
      arr.slice(i * size, i * size + size),
    )

  const posts = chunk(recentPosts, 2)!

  if (recentPosts.length === 0) {
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
        <div className={clsx('row', styles.list)}>
          {posts.map((postGroup, index) => (
            <div className="col col-6" key={index}>
              {postGroup.map(post => (
                <BlogItem key={post.id} post={post} />
              ))}
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
