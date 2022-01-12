/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import React from 'react';

import Layout from '@theme/Layout';
import BlogPostItem from "@theme/BlogPostItem";
import Link from '@docusaurus/Link';
import BlogSidebar from '@theme/BlogSidebar';
import { translate } from '@docusaurus/Translate';
import { ThemeClassNames } from '@docusaurus/theme-common';

function getCategoryOfTag(tag: string) {
  // tag's category should be customizable
  return tag[0].toUpperCase();
}

function BlogTagsListPage(props): JSX.Element {
  const { tags, sidebar, items } = props;
  const title = translate({
    id: 'theme.tags.tagsPageTitle',
    message: 'Tags',
    description: 'The title of the tag list page',
  });

  const tagCategories: { [category: string]: string[] } = {};
  Object.keys(tags).forEach((tag) => {
    const category = getCategoryOfTag(tag);
    tagCategories[category] = tagCategories[category] || [];
    tagCategories[category].push(tag);
  });
  const tagsList = Object.entries(tagCategories).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  const tagsSection = tagsList
    .map(([category, tagsForCategory]) => (
      <div key={category} style={{ "display": "flex", "flexWrap": "wrap" }}>
        {tagsForCategory.map((tag, index) => (
          <Link
            className={`post__tags margin-horiz--sm margin-bottom--sm`}
            href={tags[tag].permalink}
            key={tag}>

            {tags[tag].name} ({tags[tag].count})
          </Link>
        ))}
      </div>
    ))
    .filter((item) => item != null);

  const renderTags = () => {
    return (
      (tags.length > 0) && (
        <div className="post__tags-container margin-top--none margin-bottom--md">
          {tags.length > 0 && (
            <>
              {tags
                .slice(0, 4)
                .map(({ label, permalink: tagPermalink }, index) => (
                  <Link
                    key={tagPermalink}
                    className={`post__tags ${index > 0 ? "margin-horiz--sm" : "margin-right--sm"
                      }`}
                    to={tagPermalink}
                    style={{ fontSize: "0.75em", fontWeight: 500 }}
                  >
                    {label}
                  </Link>
                ))}
            </>
          )}
        </div>
      )
    );
  };

  return (
    <Layout
      title={title}
      wrapperClassName={ThemeClassNames.wrapper.blogPages}
      pageClassName={ThemeClassNames.page.blogTagsListPage}
      searchMetadatas={{
        // assign unique search tag to exclude this page from search results!
        tag: 'blog_tags_list',
      }}>
      <div className="container margin-vert--lg">
        <div className="row">
          <aside className="col col--3">
            <BlogSidebar sidebar={sidebar} />
          </aside>
          <main className="col col--7">
            <h1>标签</h1>
            {renderTags()}
            <div style={{ display: 'flex', flexWrap: 'wrap' }}>{tagsSection}</div>
            {/* <section className="margin-vert--lg">{tagsSection}</section> */}
            {/* {<div className="margin-vert--xl">
              {items.map(({ content: BlogPostContent }) => (
                <BlogPostItem
                  key={BlogPostContent.metadata.permalink}
                  frontMatter={BlogPostContent.frontMatter}
                  metadata={BlogPostContent.metadata}
                  truncated
                >
                  <BlogPostContent />
                </BlogPostItem>
              ))}
            </div>} */}
          </main>
        </div>
      </div>
    </Layout>
  );
}




export default BlogTagsListPage;
