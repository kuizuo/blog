import React, { useState } from 'react'
import clsx from 'clsx'
import {
  PageMetadata,
  HtmlClassNameProvider,
  ThemeClassNames,
  translateTagsPageTitle,
} from '@docusaurus/theme-common'
import Layout from '@theme/Layout'
import TagsListByLetter from '@theme/TagsListByLetter'
import SearchMetadata from '@theme/SearchMetadata'
import type { Props } from '@theme/DocTagsListPage'
import { Icon } from '@iconify/react'

import { TagsListByFlat } from '../TagsListByLetter'

export default function DocTagsListPage({ tags }: Props): JSX.Element {
  const title = translateTagsPageTitle()

  const [type, setType] = useState('letter')

  return (
    <HtmlClassNameProvider
      className={clsx(
        ThemeClassNames.wrapper.docsPages,
        ThemeClassNames.page.docsTagsListPage,
      )}
    >
      <PageMetadata title={title} />
      <SearchMetadata tag="doc_tags_list" />
      <Layout>
        <div className="container margin-vert--lg">
          <div className="row">
            <main className="col col--8 col--offset-2">
              <div className="blogtag__swith-view">
                <h1>{title}</h1>
                <div>
                  <div>
                    <Icon
                      icon="ph:list"
                      width="24"
                      height="24"
                      onClick={() => setType('list')}
                      color={
                        type === 'list' ? 'var(--ifm-color-primary)' : '#ccc'
                      }
                    />
                    <Icon
                      icon="ph:grid-four"
                      width="24"
                      height="24"
                      onClick={() => setType('grid')}
                      color={
                        type === 'grid' ? 'var(--ifm-color-primary)' : '#ccc'
                      }
                    />
                  </div>
                </div>
              </div>
              {type === 'letter' && <TagsListByLetter tags={tags} />}
              {type === 'flat' && <TagsListByFlat tags={tags} />}
            </main>
          </div>
        </div>
      </Layout>
    </HtmlClassNameProvider>
  )
}
