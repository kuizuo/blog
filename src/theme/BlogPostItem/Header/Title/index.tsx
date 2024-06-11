import Link from '@docusaurus/Link'
import { useBlogPost } from '@docusaurus/theme-common/internal'
import { cn } from '@site/src/lib/utils'
import type { Props } from '@theme/BlogPostItem/Header/Title'
import React from 'react'

import styles from './styles.module.css'

export default function BlogPostItemHeaderTitle({ className }: Props): JSX.Element {
  const { metadata, isBlogPostPage } = useBlogPost()
  const { permalink, title } = metadata
  const TitleHeading = isBlogPostPage ? 'h1' : 'h2'
  return (
    <TitleHeading className={cn(styles.title, className)} itemProp="headline">
      {isBlogPostPage ? (
        title
      ) : (
        <Link itemProp="url" to={permalink} className={styles.titleLink}>
          {title}
        </Link>
      )}
    </TitleHeading>
  )
}
