import React, { useContext, useEffect, useState } from 'react'
import { MDXProvider } from '@mdx-js/react'

import Head from '@docusaurus/Head'
import Link from '@docusaurus/Link'
import MDXComponents from '@theme/MDXComponents'
import useBaseUrl from '@docusaurus/useBaseUrl'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'

import { useColorMode } from '@docusaurus/theme-common'

import styles from './styles.module.css'
import { MarkdownSection, StyledBlogItem } from './style'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faTags } from '@fortawesome/free-solid-svg-icons'

import BlogPostAuthors from '@theme/BlogPostAuthors'
import dayjs from 'dayjs'

function BlogPostItem(props) {
  const { children, frontMatter, metadata, truncated, isBlogPostPage = false, assets } = props
  const { date, permalink, tags, authors, readingTime } = metadata

  const {
    siteConfig: { title: siteTitle, url: siteUrl },
  } = useDocusaurusContext()

  const { slug: postId, title, image } = frontMatter
  const imageUrl = useBaseUrl(image, { absolute: true })

  const theme = useColorMode()
  const isDark = theme.colorMode === 'dark'

  const renderPostHeader = () => {
    const TitleHeading = isBlogPostPage ? 'h1' : 'h2'

    return (
      <header>
        <TitleHeading className={styles.blogPostTitle} itemProp='headline'>
          {isBlogPostPage ? (
            title
          ) : (
            <Link itemProp='url' to={permalink}>
              {title}
            </Link>
          )}
        </TitleHeading>
        <div className='margin-vert--md'>
          <time dateTime={date} className={styles.blogPostDate}>
            {dayjs(date).format('YYYY-MM-DD')}
            {!isBlogPostPage && readingTime && <> · {Math.ceil(readingTime)} min read</>}
            {isBlogPostPage && readingTime && <> · 预计阅读时间 {Math.ceil(readingTime)} 分钟</>}
          </time>
          {renderTags()}
        </div>

        {isBlogPostPage && authors && <BlogPostAuthors authors={authors} assets={assets} />}
      </header>
    )
  }

  const renderTags = (isBlogPostPage = false) => {
    return (
      (tags.length > 0 || truncated) && (
        <div className='post__tags-container' style={{ display: 'inline-block' }}>
          {tags.length > 0 && (
            <>
              <FontAwesomeIcon
                icon={faTags}
                color='#c4d3e0'
                className={`${isBlogPostPage ? 'margin-left--md' : 'margin-left--sm'} margin-right--sm`}
                style={{ verticalAlign: 'middle' }}
              />
              {tags.slice(0, 4).map(({ label, permalink: tagPermalink }, index) => (
                <Link
                  key={tagPermalink}
                  className={`post__tags margin-right--sm`}
                  to={tagPermalink}
                  style={{ fontSize: '0.75em', padding: '5px' }}
                >
                  {label}
                </Link>
              ))}
            </>
          )}
        </div>
      )
    )
  }

  const renderCopyright = () => {
    return (
      <div className='post-copyright'>
        <div className='post-copyright__author'>
          <span className='post-copyright-meta'>作者:</span>{' '}
          <span className='post-copyright-info'>
            <a>{authors.map((a) => a.name).join(',')}</a>
          </span>
        </div>
        <div className='post-copyright__type'>
          <span className='post-copyright-meta'>链接:</span>{' '}
          <span className='post-copyright-info'>
            <a href={siteUrl + permalink}>{siteUrl + permalink}</a>
          </span>
        </div>
        <div className='post-copyright__notice'>
          <span className='post-copyright-meta'>来源:</span>{' '}
          <span className='post-copyright-info'>
            <a href={siteUrl}>{siteTitle}</a> 著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
          </span>
        </div>
      </div>
    )
  }

  return (
    <StyledBlogItem
      isDark={isDark}
      isBlogPostPage={isBlogPostPage}
      // className={isBlogPostPage ? "margin-top--xl" : ""}
    >
      <Head>
        {image && <meta property='og:image' content={imageUrl} />}
        {image && <meta property='twitter:image' content={imageUrl} />}
        {image && <meta name='twitter:image:alt' content={`Image for ${title}`} />}
      </Head>

      <div className={`row ${!isBlogPostPage ? 'blog-list--item' : ''}`} style={{ margin: '0px' }}>
        <div className={`col ${isBlogPostPage ? `col--12 article__details` : `col--12`}`}>
          {/* 博文部分 */}
          <article className={!isBlogPostPage ? undefined : undefined}>
            {/* 标题 */}
            {renderPostHeader()}
            {/* 正文 */}
            <MarkdownSection isBlogPostPage={isBlogPostPage} isDark={isDark} className='markdown'>
              <MDXProvider components={MDXComponents}>{children}</MDXProvider>
            </MarkdownSection>
          </article>
          <footer className='article__footer padding-top--md margin-top--sm margin-bottom--sm'>
            {isBlogPostPage && authors && renderCopyright()}
            <span className='footer__read_count'></span>
            {truncated && (
              <Link to={metadata.permalink} aria-label={`阅读 ${title} 的全文`}>
                <strong className={styles.readMore}>阅读全文</strong>
              </Link>
            )}
          </footer>
        </div>
      </div>
    </StyledBlogItem>
  )
}

export default BlogPostItem
