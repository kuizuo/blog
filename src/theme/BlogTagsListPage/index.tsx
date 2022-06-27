import React, { useState } from 'react'
import clsx from 'clsx'
import { PageMetadata, HtmlClassNameProvider, ThemeClassNames, translateTagsPageTitle } from '@docusaurus/theme-common'
import BlogLayout from '@theme/BlogLayout'
import TagsListByLetter from '@theme/TagsListByLetter'
import { TagsListByFlat } from '../TagsListByLetter'
import type { Props } from '@theme/BlogTagsListPage'
import SearchMetadata from '@theme/SearchMetadata'

import ListFilter from '@site/static/icons/list.svg'
import CardFilter from '@site/static/icons/card.svg'

export default function BlogTagsListPage({ tags, sidebar }: Props): JSX.Element {
  const title = translateTagsPageTitle()

  const [type, setType] = useState('letter')

  return (
    <HtmlClassNameProvider className={clsx(ThemeClassNames.wrapper.blogPages, ThemeClassNames.page.blogTagsListPage)}>
      <PageMetadata title={title} />
      <SearchMetadata tag='blog_tags_list' />
      <BlogLayout sidebar={sidebar}>
        <div className='blogtag__swith-view'>
          <h1>{title}</h1>
          <div>
            <ListFilter onClick={() => setType('letter')} className={type === 'letter' ? 'bloghome__switch--selected' : 'bloghome__switch'} />
            <CardFilter onClick={() => setType('flat')} className={type === 'flat' ? 'bloghome__switch--selected' : 'bloghome__switch'} />
          </div>
        </div>
        {type === 'letter' && <TagsListByLetter tags={tags} />}
        {type === 'flat' && <TagsListByFlat tags={tags} />}
      </BlogLayout>
    </HtmlClassNameProvider>
  )
}
