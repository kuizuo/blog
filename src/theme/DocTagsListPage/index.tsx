/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

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

import ListFilter from '@site/static/icons/list.svg'
import GridFilter from '@site/static/icons/grid.svg'
import { TagsListByFlat } from '../TagsListByLetter'

export default function DocTagsListPage({ tags }: Props): JSX.Element {
  const title = translateTagsPageTitle()

  const [type, setType] = useState('letter')

  return (
    <HtmlClassNameProvider
      className={clsx(ThemeClassNames.wrapper.docsPages, ThemeClassNames.page.docsTagsListPage)}
    >
      <PageMetadata title={title} />
      <SearchMetadata tag='doc_tags_list' />
      <Layout>
        <div className='container margin-vert--lg'>
          <div className='row'>
            <main className='col col--8 col--offset-2'>
              <div className='blogtag__swith-view'>
                <h1>{title}</h1>
                <div>
                  <ListFilter
                    onClick={() => setType('letter')}
                    className={
                      type === 'letter' ? 'bloghome__switch--selected' : 'bloghome__switch'
                    }
                  />
                  <GridFilter
                    onClick={() => setType('flat')}
                    className={type === 'flat' ? 'bloghome__switch--selected' : 'bloghome__switch'}
                  />
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
