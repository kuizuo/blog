import React, { useEffect } from 'react'
import clsx from 'clsx'
import { PageMetadata, HtmlClassNameProvider, ThemeClassNames } from '@docusaurus/theme-common'
import BlogLayout from '@theme/BlogLayout'
import BlogPostItem from '@theme/BlogPostItem'
import BlogPostPaginator from '@theme/BlogPostPaginator'
import BackToTopButton from '@theme/BackToTopButton'
import type { Props } from '@theme/BlogPostPage'
import BlogComment from '@site/src/components/BlogComment'
import TOC from '@theme/TOC'

function BlogPostPageMetadata(props: Props): JSX.Element {
  const { content: BlogPostContents } = props
  const { assets, metadata } = BlogPostContents
  const { title, description, date, tags, authors, frontMatter } = metadata
  const { keywords } = frontMatter
  const image = assets.image ?? frontMatter.image

  useEffect(() => {
    document.title = title
  }, [])

  return (
    <PageMetadata title={title} description={description} keywords={keywords} image={image}>
      <meta property='og:title' content={title} />
      <meta property='og:type' content='article' />
      <meta property='article:published_time' content={date} />
      {authors.some((author) => author.url) && (
        <meta
          property='article:author'
          content={authors
            .map((author) => author.url)
            .filter(Boolean)
            .join(',')}
        />
      )}
      {tags.length > 0 && (
        <meta property='article:tag' content={tags.map((tag) => tag.label).join(',')} />
      )}
    </PageMetadata>
  )
}

function BlogPostPageContent(props: Props): JSX.Element {
  const { content: BlogPostContents, sidebar } = props
  const { assets, metadata } = BlogPostContents
  const { nextItem, prevItem, frontMatter } = metadata
  const {
    hide_table_of_contents: hideTableOfContents,
    toc_min_heading_level: tocMinHeadingLevel,
    toc_max_heading_level: tocMaxHeadingLevel,
  } = frontMatter
  return (
    <BlogLayout
      // sidebar={sidebar}
      toc={
        !hideTableOfContents && BlogPostContents.toc && BlogPostContents.toc.length > 0 ? (
          <TOC
            toc={BlogPostContents.toc}
            minHeadingLevel={tocMinHeadingLevel}
            maxHeadingLevel={tocMaxHeadingLevel}
          />
        ) : undefined
      }
    >
      <BackToTopButton />
      <BlogPostItem frontMatter={frontMatter} assets={assets} metadata={metadata} isBlogPostPage>
        <BlogPostContents />
      </BlogPostItem>

      {(nextItem || prevItem) && <BlogPostPaginator nextItem={nextItem} prevItem={prevItem} />}
      <BlogComment />
    </BlogLayout>
  )
}

export default function BlogPostPage(props: Props): JSX.Element {
  return (
    <HtmlClassNameProvider
      className={clsx(ThemeClassNames.wrapper.blogPages, ThemeClassNames.page.blogPostPage)}
    >
      <BlogPostPageMetadata {...props} />
      <BlogPostPageContent {...props} />
    </HtmlClassNameProvider>
  )
}
