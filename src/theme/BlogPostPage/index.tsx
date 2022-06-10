import React from 'react'
import BlogLayout from '@theme/BlogLayout'
import BlogPostItem from '@theme/BlogPostItem'
import BlogPostPaginator from '@theme/BlogPostPaginator'
import BackToTopButton from '@theme/BackToTopButton'
import { ThemeClassNames } from '@docusaurus/theme-common'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import TOC from '@theme/TOC'

import BrowserOnly from '@docusaurus/BrowserOnly'
import Gitalk from 'gitalk'
import GitalkComponent from 'gitalk/dist/gitalk-component'
import 'gitalk/dist/gitalk.css'

function BlogPostPage(props) {
  const { content: BlogPostContents, sidebar } = props
  const { frontMatter, assets, metadata } = BlogPostContents
  const { title, permalink, description, nextItem, prevItem, date, tags, authors } = metadata
  const { hide_table_of_contents: hideTableOfContents, toc_min_heading_level: tocMinHeadingLevel, toc_max_heading_level: tocMaxHeadingLevel } = frontMatter

  const { siteConfig } = useDocusaurusContext()
  const { url: siteUrl, themeConfig } = siteConfig
  const gitalkOptions: Gitalk.GitalkOptions = themeConfig.gitalk as Gitalk.GitalkOptions

  const options: Gitalk.GitalkOptions = {
    ...gitalkOptions,
    id: title,
    title: title,
    labels: tags.length > 0 ? tags.map((t) => t.label) : ['Gitalk', title],
    body: siteUrl + permalink + '\n' + description,
    distractionFreeMode: false,
  }

  return (
    <BlogLayout
      wrapperClassName={ThemeClassNames.wrapper.blogPages}
      sidebar={sidebar}
      toc={
        !hideTableOfContents && BlogPostContents.toc && BlogPostContents.toc.length > 0 ? (
          <TOC toc={BlogPostContents.toc} minHeadingLevel={tocMinHeadingLevel} maxHeadingLevel={tocMaxHeadingLevel} />
        ) : undefined
      }
    >
      <BackToTopButton />
      <div>
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
        {tags.length > 0 && <meta property='article:tag' content={tags.map((tag) => tag.label).join(',')} />}
      </div>

      <BlogPostItem frontMatter={frontMatter} assets={assets} metadata={metadata} isBlogPostPage>
        <BlogPostContents />
      </BlogPostItem>
      {(nextItem || prevItem) && <BlogPostPaginator nextItem={nextItem} prevItem={prevItem} />}

      <BrowserOnly fallback={<div></div>}>{() => <GitalkComponent options={options} />}</BrowserOnly>
    </BlogLayout>
  )
}

export default BlogPostPage
