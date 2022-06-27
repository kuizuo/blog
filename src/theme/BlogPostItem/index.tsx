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
import { faTags, faUser, faCalendar, faClock } from '@fortawesome/free-solid-svg-icons'

import BlogPostAuthors from '@theme/BlogPostAuthors'
import type { Props } from '@theme/BlogPostItem'
import dayjs from 'dayjs'
import { IconProp } from '@fortawesome/fontawesome-svg-core'

function BlogPostItem(props: Props) {
  const { children, frontMatter, metadata, truncated, isBlogPostPage = false, assets } = props
  const { date, permalink, tags, authors, readingTime } = metadata

  const {
    siteConfig: { title: siteTitle, url: siteUrl },
  } = useDocusaurusContext()

  const { slug: postId, title, image } = frontMatter
  const imageUrl = useBaseUrl(image, { absolute: true })

  const theme = useColorMode()
  const isDark = theme.colorMode === 'dark'

  const rendenPostTags = () => {
    return (
      <>
        {tags.length > 0 && (
          <>
            <FontAwesomeIcon icon={faTags as IconProp} color='#c4d3e0' />
            {tags.slice(0, 4).map(({ label, permalink: tagPermalink }, index) => (
              <Link key={tagPermalink} className={`post__tags`} to={tagPermalink} style={{ fontSize: '0.75em', padding: '1px 5px' }}>
                {label}
              </Link>
            ))}
          </>
        )}
      </>
    )
  }

  const renderPostHeader = () => {
    const TitleHeading = isBlogPostPage ? 'h1' : 'h2'

    return (
      <header>
        <TitleHeading itemProp='headline'>
          {isBlogPostPage ? (
            title
          ) : (
            <Link itemProp='url' to={permalink} className={styles.blogPostTitle}>
              {title}
            </Link>
          )}
        </TitleHeading>
        {isBlogPostPage && (
          <div className={styles.blogPostInfo}>
            <time dateTime={date} className={styles.blogPostDate}>
              {dayjs(date).format('YYYY-MM-DD')}
              {isBlogPostPage && readingTime && <> · {Math.ceil(readingTime)} 分钟阅读 </>}
            </time>
            {rendenPostTags()}
          </div>
        )}
        {isBlogPostPage && authors && <BlogPostAuthors authors={authors} assets={assets} />}
      </header>
    )
  }

  const renderPostInfo = () => {
    return (
      <>
        <hr />
        <div className={styles.blogPostInfo}>
          <FontAwesomeIcon icon={faUser as IconProp} color='#c4d3e0' />
          {authors.map((a) => (
            <span key={a.url}>
              <a href={a.url} className={styles.blogPostAuthor}>
                {a.name}
              </a>
            </span>
          ))}
          <FontAwesomeIcon icon={faCalendar as IconProp} color='#c4d3e0' />
          <time dateTime={date} className={styles.blogPostDate}>
            {dayjs(date).format('YYYY-MM-DD')}
          </time>
          {rendenPostTags()}
          <FontAwesomeIcon icon={faClock as IconProp} color='#c4d3e0' />
          {readingTime && <span className={styles.blogPostReadTime}>{Math.ceil(readingTime)} 分钟阅读</span>}
        </div>
      </>
    )
  }

  const renderCopyright = () => {
    return (
      <div className={styles.blogPostCopyright}>
        <div className={styles.blogPostCopyrightAuthor}>
          <span className={styles.blogPostCopyrightMeta}>作者:</span> <a>{authors.map((a) => a.name).join(',')}</a>
        </div>
        <div>
          <span className={styles.blogPostCopyrightMeta}>链接:</span> <a href={siteUrl + permalink}>{siteUrl + permalink}</a>
        </div>
        <div>
          <span className={styles.blogPostCopyrightMeta}>来源:</span> <a href={siteUrl}>{siteTitle}</a> 著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
        </div>
      </div>
    )
  }

  return (
    <StyledBlogItem isDark={isDark} isBlogPostPage={isBlogPostPage}>
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
            {/* 信息 */}
            {!isBlogPostPage && renderPostInfo()}
            {/* 底部 */}
            {isBlogPostPage && (
              <footer className='article__footer padding-top--md margin-top--sm margin-bottom--sm'>
                {/* 版权 */}
                {isBlogPostPage && authors && renderCopyright()}
                <span className='footer__read_count'></span>
              </footer>
            )}
          </article>
        </div>
      </div>
    </StyledBlogItem>
  )
}

export default BlogPostItem
