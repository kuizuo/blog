/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import type { ArchiveBlogPost, Props } from '@theme/BlogArchivePage';
import styles from './styles.module.css'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCalendar, faHistory } from '@fortawesome/free-solid-svg-icons';

import dayjs from 'dayjs'

type YearProp = {
  year: string;
  posts: ArchiveBlogPost[];
};

function Year({ posts }: YearProp) {
  return (
    <>
      <ul>
        {posts.map((post) => (
          <li key={post.metadata.permalink}>
            <Link to={post.metadata.permalink}>
              <span>{dayjs(post.metadata.date).format('MM-DD')}</span>
              {post.metadata.title}
            </Link>
          </li>
        ))}
      </ul>
    </>
  );
}

function YearsSection({ years }: { years: YearProp[] }) {
  return (
    <div>
      {years.map((_props, idx) => (
        <div key={idx} className="margin-vert--lg">
          <h3>
            {_props.year}<span><i>{years[idx].posts.length}</i> 篇</span>
          </h3>
          <Year {..._props} />
        </div>
      ))}
    </div>
  );
}

function listPostsByYears(blogPosts: ArchiveBlogPost[]): YearProp[] {
  const postsByYear: Map<string, ArchiveBlogPost[]> = blogPosts.reduceRight(
    (posts, post) => {
      const year = post.metadata.date.split('-')[0];
      const yearPosts = posts.get(year) || [];
      return posts.set(year, [post, ...yearPosts]);
    },
    new Map(),
  );

  return Array.from(postsByYear, ([year, posts]) => ({
    year,
    posts,
  })).reverse();
}

export default function BlogArchive({ archive }: Props) {

  const years = listPostsByYears(archive.blogPosts);
  return (
    <Layout >
      <div className='container-wrapper padding-vert--md'>
        <div className='container'>
          <div className='row'>
            <div className='col'>
              <div className='archive'>
                <h2><FontAwesomeIcon icon={faCalendar} color='#338bff' /> 归档</h2>
                <div className={styles.count}>总共 {archive.blogPosts.length} 篇文章</div>
                {years.length > 0 && <YearsSection years={years} />}
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
