/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import React, { useContext, useEffect, useState } from 'react';
import clsx from 'clsx';
import { MDXProvider } from '@mdx-js/react';

import Head from '@docusaurus/Head';
import Link from '@docusaurus/Link';
import MDXComponents from '@theme/MDXComponents';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

import ThemeContext from '@theme/ThemeContext';

import styles from './styles.module.css';
import { MarkdownSection, StyledBlogItem } from './style';

import Eye from '@site/static/icons/eye.svg';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTags } from '@fortawesome/free-solid-svg-icons';

import BrowserOnly from '@docusaurus/BrowserOnly';
import Comments from '@site/src/components/Comments';
// import Ad from "@site/src/components/Ad";
// import adConfig from "@site/src/components/Ad/config";
// import Adsense from "@site/src/components/Adsense";

import Translate from '@docusaurus/Translate';

const MONTHS = ['', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

function BlogPostItem(props) {
  const { children, frontMatter, metadata, truncated, isBlogPostPage = false, views } = props;
  const { date, permalink, tags, readingTime } = metadata;

  // activityId, oid 为 B 站评论相关
  const { slug: postId, author, title, image, activityId } = frontMatter;

  const authorURL = frontMatter.author_url || frontMatter.authorURL;
  const authorTitle = frontMatter.author_title || frontMatter.authorTitle;
  const authorImageURL = frontMatter.author_image_url || frontMatter.authorImageURL;
  const imageUrl = useBaseUrl(image, { absolute: true });

  // 是否为黑暗主题：
  const theme = useContext(ThemeContext);
  const { isDarkTheme } = theme;

  // 当前语言
  const {
    i18n: { currentLocale },
  } = useDocusaurusContext();

  const dateObj = new Date(date);

  const year = dateObj.getFullYear();
  let month = dateObj.getMonth() + 1;
  const day = dateObj.getDate();

  let dateStr = `${year}年${month}月`;

  if (currentLocale === 'en') {
    month = dateObj.toLocaleString('default', { month: 'long' });
    dateStr = `${month}, ${year}`;
  }

  const renderPostHeader = () => {
    const TitleHeading = isBlogPostPage ? 'h1' : 'h2';

    return (
      <header>
        <TitleHeading className={clsx(isBlogPostPage ? 'margin-bottom--md' : 'margin-vert--md', styles.blogPostTitle, isBlogPostPage ? 'text--center' : '')}>
          {isBlogPostPage ? title : <Link to={permalink}>{title}</Link>}
        </TitleHeading>
        {
          <div className='margin-vert--md'>
            <time dateTime={date} className={styles.blogPostDate}>
              {month} {day}, {year} {readingTime && <> · {Math.ceil(readingTime)} min read</>}
            </time>
          </div>
        }
      </header>
    );
  };

  const renderTags = () => {
    return (
      (tags.length > 0 || truncated) && (
        <div className='post__tags-container margin-top--none margin-bottom--md'>
          {tags.length > 0 && (
            <>
              <FontAwesomeIcon icon={faTags} color='#c4d3e0' className='margin-right--md' />
              {tags.slice(0, 4).map(({ label, permalink: tagPermalink }, index) => (
                <Link key={tagPermalink} className={`post__tags ${index > 0 ? 'margin-horiz--sm' : 'margin-right--sm'}`} to={tagPermalink} style={{ fontSize: '0.75em', fontWeight: 500 }}>
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
    <StyledBlogItem
      isDark={isDarkTheme}
      isBlogPostPage={isBlogPostPage}
      // className={isBlogPostPage ? "margin-top--xl" : ""}
    >
      <Head>
        {image && <meta property='og:image' content={imageUrl} />}
        {image && <meta property='twitter:image' content={imageUrl} />}
        {image && <meta name='twitter:image:alt' content={`Image for ${title}`} />}
      </Head>

      {/* 统计 */}
      {isBlogPostPage && <Count title={title} />}
      <div
        className={`row 
          ${!isBlogPostPage ? 'blog-list--item' : ''}`}
        style={{ margin: 0 }}
      >
        {/* 列表页日期 */}
        {!isBlogPostPage && (
          <div className='post__date-container col col--3 padding-right--lg margin-bottom--lg'>
            <div className='post__date'>
              <div className='post__day'>{day}</div>
              <div className='post__year_month'>{dateStr}</div>
            </div>
            <div className='line__decor'></div>
          </div>
        )}
        <div className={`col ${isBlogPostPage ? `col--12 article__details` : `col--9`}`}>
          {/* 博文部分 */}
          <article className={!isBlogPostPage ? 'margin-bottom--md' : undefined}>
            {/* 标题 */}
            {renderPostHeader()}
            {/* 列表页标签 */}
            {!isBlogPostPage && renderTags()}
            {/* 发布日期与阅读时间 */}
            {isBlogPostPage && (
              <p className={`single-post--date text--center`}>
                {dateStr} ·{' '}
                <Translate id='blogpage.estimated.time' description='blog page estimated time'>
                  预计阅读时间：
                </Translate>
                {readingTime && (
                  <>
                    {' '}
                    {Math.ceil(readingTime)}{' '}
                    <Translate id='blogpage.estimated.time.label' description='blog page estimated time label'>
                      分钟
                    </Translate>
                  </>
                )}
              </p>
            )}
            {/* 标签 */}
            {isBlogPostPage && (
              <>
                <div className='text--center margin-bottom--xs padding-bottom--xs'>{renderTags()}</div>
                {/* <Adsense responsive="true" format="auto" slot="2800800187" /> */}
              </>
            )}

            {/* 正文 */}
            <MarkdownSection isBlogPostPage={isBlogPostPage} isDark={isDarkTheme} className='markdown'>
              <MDXProvider components={MDXComponents}>{children}</MDXProvider>
            </MarkdownSection>
            {/* {isBlogPostPage && (
               <div style={{ marginTop: "1em" }}>
                 {adConfig.articleFooter.map(({ id, alt, imageSrc, link }) => (
                   <Ad key={id} link={link} src={imageSrc} alt={alt} />
                 ))}
               </div>
             )} */}
            {isBlogPostPage}
          </article>
          <footer className='article__footer padding-top--md margin-top--md margin-bottom--md'>
            {!isBlogPostPage && (
              <span className='footer__read_count'>
                <Eye
                  // color={isDarkTheme ? "#76baff" : "#006dfe"}
                  className='footer__eye'
                  style={{ verticalAlign: 'middle' }}
                />{' '}
                {views}
              </span>
            )}
            {truncated && (
              <Link to={metadata.permalink} aria-label={`阅读 ${title} 的全文`}>
                <strong className={styles.readMore}>
                  <Translate description='read full text'>阅读全文</Translate>
                </strong>
              </Link>
            )}
            {/* isBlogPostPage && (
               <Comments activityId={activityId} oid={oid} bvid={bvid} />
             ) */}
          </footer>
        </div>
      </div>
    </StyledBlogItem>
  );
}

function Count({ title, ...post }) {
  return (
    <BrowserOnly fallback={<div></div>}>
      {() => {
        // if (localStorage.getItem(postId)) return null;

        const addViewCount = async () => {
          await fetch('http://blog.kuizuo.cn/posts/increase_view', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ title }),
          });
          // localStorage.setItem(postId, true);
        };

        useEffect(() => {
          addViewCount();
        }, []);
        return null;
      }}
    </BrowserOnly>
  );
}

export default BlogPostItem;
