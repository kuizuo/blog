import React from 'react';
import Link from '@docusaurus/Link';
import {translate} from '@docusaurus/Translate';
import {PageMetadata} from '@docusaurus/theme-common';
import Layout from '@theme/Layout';
import type {ArchiveBlogPost, Props} from '@theme/BlogArchivePage';
import {FontAwesomeIcon} from '@fortawesome/react-fontawesome';
import {faArchive} from '@fortawesome/free-solid-svg-icons';
import {IconProp} from '@fortawesome/fontawesome-svg-core';
import styles from './styles.module.css';

import dayjs from 'dayjs';

type YearProp = {
  year: string;
  posts: ArchiveBlogPost[];
};

function Year({posts}: YearProp) {
  return (
    <>
      <ul className={styles.archiveList}>
        {posts.map((post) => (
          <li key={post.metadata.permalink} className={styles.archiveItem}>
            <Link to={post.metadata.permalink}>
              <time className={styles.archiveTime}>
                {dayjs(post.metadata.date).format('MM-DD')}
              </time>
              <span>{post.metadata.title}</span>
            </Link>
          </li>
        ))}
      </ul>
    </>
  );
}

function YearsSection({years}: {years: YearProp[]}) {
  return (
    <div className="margin-top--md margin-left--sm">
      {years.map((_props, idx) => (
        <div key={idx}>
          <h3 className={styles.archiveYear}>
            {_props.year}
            <span>
              <i>{(years[idx] as YearProp).posts.length}</i> 篇
            </span>
          </h3>?.
          <Year {..._props} />
        </div>
      ))}
    </div>
  );
}

function listPostsByYears(blogPosts: readonly ArchiveBlogPost[]): YearProp[] {
  const postsByYear = blogPosts.reduceRight((posts, post) => {
    const year = post.metadata.date.split('-')[0]!;
    const yearPosts = posts.get(year) ?? [];
    return posts.set(year, [post, ...yearPosts]);
  }, new Map<string, ArchiveBlogPost[]>());

  return Array.from(postsByYear, ([year, posts]) => ({
    year,
    posts,
  })).reverse();
}

export default function BlogArchive({archive}: Props) {
  const title = translate({
    id: 'theme.blog.archive.title',
    message: 'Archive',
    description: 'The page & hero title of the blog archive page',
  });
  const description = translate({
    id: 'theme.blog.archive.description',
    message: 'Archive',
    description: 'The page & hero description of the blog archive page',
  });

  const years = listPostsByYears(archive.blogPosts);
  return (
    <>
      <PageMetadata title={title} description={description} />
      <Layout>
        <div className="container-wrapper padding-vert--md">
          <div className={styles.archive}>
            <h2>
              <FontAwesomeIcon icon={faArchive as IconProp} color="#23affc" />{' '}
              归档
            </h2>
            <div className={styles.archiveCount}>
              总共 {archive.blogPosts.length} 篇文章
            </div>
            {years.length > 0 && <YearsSection years={years} />}
          </div>
        </div>
      </Layout>
    </>
  );
}
