import React, { useState } from 'react'
import clsx from 'clsx'
import {
  PageMetadata,
  HtmlClassNameProvider,
  ThemeClassNames,
  translateTagsPageTitle,
} from '@docusaurus/theme-common'
import TagsListByLetter from '@theme/TagsListByLetter'
import { TagsListByFlat } from '../TagsListByLetter'
import type { Props } from '@theme/BlogTagsListPage'
import SearchMetadata from '@theme/SearchMetadata'
import { Icon } from '@iconify/react'

import MyLayout from '../MyLayout'

export default function BlogTagsListPage({
  tags,
  sidebar,
}: Props): JSX.Element {
  const title = translateTagsPageTitle()

  const [type, setType] = useState<'list' | 'grid'>('list')

  return (
    <HtmlClassNameProvider
      className={clsx(
        ThemeClassNames.wrapper.blogPages,
        ThemeClassNames.page.blogTagsListPage,
      )}
    >
      <PageMetadata title={title} />
      <SearchMetadata tag="blog_tags_list" />
      <MyLayout>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <h1>{title}</h1>
          <span>
            <Icon
              icon="ph:list"
              width="24"
              height="24"
              onClick={() => setType('list')}
              color={type === 'list' ? 'var(--ifm-color-primary)' : '#ccc'}
            />
            <Icon
              icon="ph:grid-four"
              width="24"
              height="24"
              onClick={() => setType('grid')}
              color={type === 'grid' ? 'var(--ifm-color-primary)' : '#ccc'}
            />
          </span>
        </div>
        {type === 'list' && <TagsListByLetter tags={tags} />}
        {type === 'grid' && <TagsListByFlat tags={tags} />}
      </MyLayout>
    </HtmlClassNameProvider>
  )
}
