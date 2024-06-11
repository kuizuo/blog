import { useBlogPost } from '@docusaurus/theme-common/internal'
import { blogPostContainerID } from '@docusaurus/utils-common'
import { cn } from '@site/src/lib/utils'
import type { Props } from '@theme/BlogPostItem/Content'
import MDXContent from '@theme/MDXContent'
import React from 'react'

export default function BlogPostItemContent({ children, className }: Props): JSX.Element {
  const { isBlogPostPage } = useBlogPost()
  return (
    <div
      // This ID is used for the feed generation to locate the main content
      id={isBlogPostPage ? blogPostContainerID : undefined}
      className={cn('markdown', className)}
      itemProp="articleBody"
      style={{ position: 'relative' }}
    >
      <MDXContent>{children}</MDXContent>
    </div>
  )
}
