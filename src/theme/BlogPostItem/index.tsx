import { useBlogPost } from '@docusaurus/theme-common/internal'
import type { Props } from '@theme/BlogPostItem'
import BlogPostItemContainer from '@theme/BlogPostItem/Container'
import BlogPostItemContent from '@theme/BlogPostItem/Content'
import BlogPostItemFooter from '@theme/BlogPostItem/Footer'
import BlogPostItemHeader from '@theme/BlogPostItem/Header'
import clsx from 'clsx'
import React from 'react'

// apply a bottom margin in list view
function useContainerClassName() {
  const { isBlogPostPage } = useBlogPost()
  return !isBlogPostPage ? 'blog-card margin-bottom--lg' : ''
}

export default function BlogPostItem({ children, className }: Props): JSX.Element {
  const containerClassName = useContainerClassName()
  return (
    <BlogPostItemContainer className={clsx(containerClassName, className)}>
      <BlogPostItemHeader />
      <BlogPostItemContent>{children}</BlogPostItemContent>
      <BlogPostItemFooter />
    </BlogPostItemContainer>
  )
}
