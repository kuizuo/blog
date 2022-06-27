import React from 'react'
import clsx from 'clsx'
import { PageMetadata, HtmlClassNameProvider, ThemeClassNames, translateTagsPageTitle } from '@docusaurus/theme-common'
import BlogLayout from '@theme/BlogLayout'
import TagsListByLetter from '@theme/TagsListByLetter'
import type { Props } from '@theme/BlogTagsListPage'
import SearchMetadata from '@theme/SearchMetadata'

export default function BlogTagsListPage({ tags, sidebar }: Props): JSX.Element {
  const title = translateTagsPageTitle()
  return (
    <HtmlClassNameProvider className={clsx(ThemeClassNames.wrapper.blogPages, ThemeClassNames.page.blogTagsListPage)}>
      <PageMetadata title={title} />
      <SearchMetadata tag='blog_tags_list' />
      <BlogLayout sidebar={sidebar}>
        <h1>{title}</h1>
        <TagsListByLetter tags={tags} />
      </BlogLayout>
    </HtmlClassNameProvider>
  )
}
