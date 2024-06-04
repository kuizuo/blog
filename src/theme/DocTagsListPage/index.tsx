import { HtmlClassNameProvider, PageMetadata, ThemeClassNames, translateTagsPageTitle } from '@docusaurus/theme-common'
import { Icon } from '@iconify/react'
import { cn } from '@site/src/lib/utils'
import type { Props } from '@theme/DocTagsListPage'
import SearchMetadata from '@theme/SearchMetadata'
import TagsListByLetter from '@theme/TagsListByLetter'
import React, { useState } from 'react'

import MyLayout from '../MyLayout'
import { TagsListByFlat } from '../TagsListByLetter'

export default function DocTagsListPage({ tags }: Props): JSX.Element {
  const title = translateTagsPageTitle()

  const [type, setType] = useState('letter')

  return (
    <HtmlClassNameProvider className={cn(ThemeClassNames.wrapper.docsPages, ThemeClassNames.page.docsTagsListPage)}>
      <PageMetadata title={title} />
      <SearchMetadata tag="doc_tags_list" />
      <MyLayout>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <h1>{title}</h1>
          <div>
            <div>
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
            </div>
          </div>
        </div>
        {type === 'letter' && <TagsListByLetter tags={tags} />}
        {type === 'flat' && <TagsListByFlat tags={tags} />}
      </MyLayout>
    </HtmlClassNameProvider>
  )
}
