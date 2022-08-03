import React from 'react';
import {BlogPostProvider} from '@docusaurus/theme-common/internal';
import BlogPostItem from '@theme/BlogPostItem';
import type {Props} from '@theme/BlogPostItems';

export default function BlogPostItems({
  items,
  component: BlogPostItemComponent = BlogPostItem,
}: Props): JSX.Element {
  return (
    <>
      {items.map(({content: BlogPostContent}) => (
        <BlogPostProvider
          key={BlogPostContent.metadata.permalink}
          content={BlogPostContent}>
          <BlogPostItemComponent>
            <BlogPostContent />
          </BlogPostItemComponent>
        </BlogPostProvider>
      ))}
    </>
  );
}
