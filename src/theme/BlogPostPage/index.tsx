import React from 'react';
import Seo from '@theme/Seo';
import BlogLayout from '@theme/BlogLayout';
import BlogPostItem from '@theme/BlogPostItem';
import BlogPostPaginator from '@theme/BlogPostPaginator';
import BackToTopButton from '@theme/BackToTopButton';
import { ThemeClassNames } from '@docusaurus/theme-common';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import TOC from '@theme/TOC';

import BrowserOnly from '@docusaurus/BrowserOnly';
import 'gitalk/dist/gitalk.css';
import GitalkComponent from 'gitalk/dist/gitalk-component';

import useViews from './useViews';

function BlogPostPage(props) {
  const { content: BlogPostContents, sidebar } = props;
  const {
    // TODO this frontmatter is not validated/normalized, it's the raw user-provided one. We should expose normalized one too!
    frontMatter,
    assets,
    metadata,
  } = BlogPostContents;
  const { title, permalink, description, nextItem, prevItem, date, tags, authors } = metadata;
  const { hide_table_of_contents: hideTableOfContents, keywords, toc_min_heading_level: tocMinHeadingLevel, toc_max_heading_level: tocMaxHeadingLevel } = frontMatter;

  const {
    siteConfig: { url: siteUrl },
  } = useDocusaurusContext();

  const views = useViews(props.content);

  const labels = tags.length > 0 ? tags.map((t) => t.label) : ['Gitalk', title];
  const options = {
    clientID: '3f390a6f6e979a76d1a1',
    clientSecret: 'e2cd29b8055fcc2265b2292387236c36857e21fc',
    repo: 'blog',
    owner: 'kuizuo',
    admin: ['kuizuo'],
    id: title,
    title: title,
    labels: labels,
    body: siteUrl + permalink + '\n' + description,
    distractionFreeMode: false,
  };
  const image = assets.image ?? frontMatter.image;

  return (
    <BlogLayout
      wrapperClassName={ThemeClassNames.wrapper.blogPages}
      pageClassName={ThemeClassNames.page.blogPostPage}
      sidebar={sidebar}
      toc={
        !hideTableOfContents && BlogPostContents.toc && BlogPostContents.toc.length > 0 ? (
          <TOC toc={BlogPostContents.toc} minHeadingLevel={tocMinHeadingLevel} maxHeadingLevel={tocMaxHeadingLevel} />
        ) : undefined
      }
    >
      <BackToTopButton />
      <Seo
        // TODO refactor needed: it's a bit annoying but Seo MUST be inside BlogLayout
        // otherwise  default image (set by BlogLayout) would shadow the custom blog post image
        title={title}
        description={description}
        keywords={keywords}
        image={image}
      >
        <meta property='og:type' content='article' />
        <meta property='article:published_time' content={date} />

        {/* TODO double check those article metas array syntaxes, see https://ogp.me/#array */}
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
      </Seo>

      <BlogPostItem frontMatter={frontMatter} assets={assets} metadata={metadata} isBlogPostPage views={views}>
        <BlogPostContents />
      </BlogPostItem>
      {(nextItem || prevItem) && <BlogPostPaginator nextItem={nextItem} prevItem={prevItem} />}

      <BrowserOnly fallback={<div></div>}>{() => <GitalkComponent options={options} />}</BrowserOnly>
    </BlogLayout>
  );
}

export default BlogPostPage;
