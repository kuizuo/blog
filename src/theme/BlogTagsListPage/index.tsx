/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import React, {useState} from 'react';
import clsx from 'clsx';
import {
  PageMetadata,
  HtmlClassNameProvider,
  ThemeClassNames,
  translateTagsPageTitle,
} from '@docusaurus/theme-common';
import BlogLayout from '@theme/BlogLayout';
import TagsListByLetter from '@theme/TagsListByLetter';
import {TagsListByFlat} from '../TagsListByLetter';
import type {Props} from '@theme/BlogTagsListPage';
import SearchMetadata from '@theme/SearchMetadata';

import ListFilter from '@site/static/icons/list.svg';
import GridFilter from '@site/static/icons/grid.svg';

export default function BlogTagsListPage({tags, sidebar}: Props): JSX.Element {
  const title = translateTagsPageTitle();

  const [type, setType] = useState<'list' | 'grid'>('list');

  return (
    <HtmlClassNameProvider
      className={clsx(
        ThemeClassNames.wrapper.blogPages,
        ThemeClassNames.page.blogTagsListPage,
      )}>
      <PageMetadata title={title} />
      <SearchMetadata tag="blog_tags_list" />
      <BlogLayout sidebar={sidebar}>
        <div className="blogtag__swith-view">
          <h1>{title}</h1>
          <div>
            <ListFilter
              onClick={() => setType('list')}
              className={
                type === 'list'
                  ? 'bloghome__switch--selected'
                  : 'bloghome__switch'
              }
            />
            <GridFilter
              onClick={() => setType('grid')}
              className={
                type === 'grid'
                  ? 'bloghome__switch--selected'
                  : 'bloghome__switch'
              }
            />
          </div>
        </div>
        {type === 'list' && <TagsListByLetter tags={tags} />}
        {type === 'grid' && <TagsListByFlat tags={tags} />}
      </BlogLayout>
    </HtmlClassNameProvider>
  );
}
