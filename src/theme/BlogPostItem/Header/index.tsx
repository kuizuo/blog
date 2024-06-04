import { useBlogPost } from '@docusaurus/theme-common/internal'
import BlogPostItemHeaderAuthors from '@theme/BlogPostItem/Header/Authors'
import BlogPostItemHeaderInfo from '@theme/BlogPostItem/Header/Info'
import BlogPostItemHeaderTitle from '@theme/BlogPostItem/Header/Title'
import React from 'react'

export default function BlogPostItemHeader(): JSX.Element {
  const { isBlogPostPage } = useBlogPost()
  return (
    <header style={{ position: 'relative', zIndex: 2 }}>
      <BlogPostItemHeaderTitle />
      {isBlogPostPage && (
        <>
          <BlogPostItemHeaderInfo />
          {/* <BlogPostItemHeaderAuthors /> */}
        </>
      )}
    </header>
  )
}
