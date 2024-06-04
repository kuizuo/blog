import { useBlogPost } from '@docusaurus/theme-common/internal'
import { useBaseUrlUtils } from '@docusaurus/useBaseUrl'
import { cn } from '@site/src/lib/utils'
import type { Props } from '@theme/BlogPostItem/Container'
import React from 'react'

import styles from './styles.module.css'

export default function BlogPostItemContainer({ children, className }: Props): JSX.Element {
  const { frontMatter, assets } = useBlogPost()
  const { withBaseUrl } = useBaseUrlUtils()
  const image = assets.image ?? frontMatter.image
  return (
    <article
      className={cn(className, styles.article)}
      itemProp="blogPost"
      itemScope
      itemType="http://schema.org/BlogPosting"
    >
      {image && (
        <>
          <meta itemProp="image" content={withBaseUrl(image, { absolute: true })} />
          <div className={styles.cover}>
            <div className={styles.coverMask} style={{ backgroundImage: `url("${image}")` }} />
          </div>
          <div style={{ height: '120px' }} />
        </>
      )}
      {children}
    </article>
  )
}
