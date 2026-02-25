import { type BlogSidebar } from '@docusaurus/plugin-content-blog'
import { BlogPostProvider, useBlogPost } from '@docusaurus/plugin-content-blog/client'
import { HtmlClassNameProvider, ThemeClassNames } from '@docusaurus/theme-common'
import Comment from '@site/src/components/Comment'
import { cn } from '@site/src/lib/utils'
import BackToTopButton from '@theme/BackToTopButton'
import BlogLayout from '@theme/BlogLayout'
import BlogPostItem from '@theme/BlogPostItem'
import type { Props } from '@theme/BlogPostPage'
import BlogPostPageMetadata from '@theme/BlogPostPage/Metadata'
import BlogPostPaginator from '@theme/BlogPostPaginator'
import TOC from '@theme/TOC'
import { type ReactNode } from 'react'

function BlogPostPageContent({
  sidebar,
  children,
}: {
  sidebar: BlogSidebar
  children: ReactNode
}): JSX.Element {
  const { metadata, toc } = useBlogPost()
  const { nextItem, prevItem, frontMatter } = metadata
  const {
    hide_table_of_contents: hideTableOfContents,
    toc_min_heading_level: tocMinHeadingLevel,
    toc_max_heading_level: tocMaxHeadingLevel,
    hide_comment: hideComment,
  } = frontMatter

  return (
    <BlogLayout
      sidebar={sidebar}
      toc={
        !hideTableOfContents && toc.length > 0
          ? (
              <TOC toc={toc} minHeadingLevel={tocMinHeadingLevel} maxHeadingLevel={tocMaxHeadingLevel} />
            )
          : undefined
      }
    >
      <BlogPostItem>{children}</BlogPostItem>

      {(nextItem || prevItem) && (
        <div className="margin-bottom--md">
          <BlogPostPaginator nextItem={nextItem} prevItem={prevItem} />
        </div>
      )}
      {!hideComment && <Comment />}
      <BackToTopButton />
    </BlogLayout>
  )
}

export default function BlogPostPage(props: Props): JSX.Element {
  const BlogPostContent = props.content
  return (
    <BlogPostProvider content={props.content} isBlogPostPage>
      <HtmlClassNameProvider className={cn(ThemeClassNames.wrapper.blogPages, ThemeClassNames.page.blogPostPage)}>
        <BlogPostPageMetadata />
        <BlogPostPageContent sidebar={props.sidebar}>
          <BlogPostContent />
        </BlogPostPageContent>
      </HtmlClassNameProvider>
    </BlogPostProvider>
  )
}
