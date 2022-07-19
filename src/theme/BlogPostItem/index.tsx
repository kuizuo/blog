import React from 'react'
import clsx from 'clsx'
import Translate, { translate } from '@docusaurus/Translate'

import Head from '@docusaurus/Head'
import Link from '@docusaurus/Link'
import MDXContent from '@theme/MDXContent'
import useBaseUrl, { useBaseUrlUtils } from '@docusaurus/useBaseUrl'

import { useColorMode, usePluralForm } from '@docusaurus/theme-common'
import { blogPostContainerID } from '@docusaurus/utils-common'
import styles from './styles.module.css'
import { MarkdownSection, StyledBlogItem } from './style'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faTags, faUser, faCalendar, faClock, faArrowRight } from '@fortawesome/free-solid-svg-icons'

import EditThisPage from '@theme/EditThisPage'
import TagsListInline from '@theme/TagsListInline'
import Tag from '@theme/Tag'
import BlogPostAuthors from '@theme/BlogPostAuthors'
import type { Props } from '@theme/BlogPostItem'
import { IconProp } from '@fortawesome/fontawesome-svg-core'

function useReadingTimePlural() {
  const { selectMessage } = usePluralForm()
  return (readingTimeFloat: number) => {
    const readingTime = Math.ceil(readingTimeFloat)
    return selectMessage(
      readingTime,
      translate(
        {
          id: 'theme.blog.post.readingTime.plurals',
          description:
            'Pluralized label for "{readingTime} min read". Use as much plural forms (separated by "|") as your language support (see https://www.unicode.org/cldr/cldr-aux/charts/34/supplemental/language_plural_rules.html)',
          message: 'One min read|{readingTime} min read',
        },
        { readingTime },
      ),
    )
  }
}

export default function BlogPostItem(props: Props): JSX.Element {
  const readingTimePlural = useReadingTimePlural()
  const { withBaseUrl } = useBaseUrlUtils()
  const { children, frontMatter, assets, metadata, truncated, isBlogPostPage = false } = props
  const { date, formattedDate, permalink, tags, readingTime, title, editUrl, authors = [] } = metadata

  const theme = useColorMode()
  const isDark = theme.colorMode === "dark"

  const image = assets.image ?? frontMatter.image
  const truncatedPost = !isBlogPostPage && truncated
  const tagsExists = tags.length > 0
  const authorsExists = authors.length > 0
  const TitleHeading = isBlogPostPage ? 'h1' : 'h2'

  return (
    <StyledBlogItem isDark={isDark} isBlogPostPage={isBlogPostPage}>
      <div className={clsx('row', !isBlogPostPage && 'blog-list--item')} style={!isBlogPostPage ? { margin: 0 } : {}}>
        <div className={clsx('col', isBlogPostPage ? `col--12 article__details` : `col--12`)}>
          {/* 博文部分 */}
          <article itemProp='blogPost' itemScope itemType='http://schema.org/BlogPosting'>
            {/* 标题 */}
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
                  <time dateTime={date} className={styles.blogPostDate} itemProp='datePublished'>
                    {formattedDate}
                    {readingTime && <> · {readingTimePlural(readingTime)} </>}
                  </time>
                </div>
              )}
              {isBlogPostPage && <BlogPostAuthors authors={authors} assets={assets} />}
            </header>
            {image && <meta itemProp='image' content={withBaseUrl(image, { absolute: true })} />}
            {/* 正文 */}
            <div id={isBlogPostPage ? blogPostContainerID : undefined} className='markdown' itemProp='articleBody'>
              <MDXContent>{children}</MDXContent>
            </div>
            {/* 信息 */}
            {!isBlogPostPage && (
              <>
                <hr />
                <div className={styles.blogPostInfo}>
                  {authorsExists && (
                    <>
                      <FontAwesomeIcon icon={faUser as IconProp} color='#c4d3e0' className='blog__author' />
                      {authors.map((a) => (
                        <span key={a.url} className='blog__author'>
                          <a href={a.url} className={styles.blogPostAuthor}>
                            {a.name}
                          </a>
                        </span>
                      ))}
                    </>
                  )}
                  {date && (
                    <>
                      <FontAwesomeIcon icon={faCalendar as IconProp} color='#c4d3e0' />
                      <time dateTime={date} className={styles.blogPostDate} itemProp='datePublished'>
                        {formattedDate}
                      </time>
                    </>
                  )}
                  {tagsExists && (
                    <>
                      <FontAwesomeIcon icon={faTags as IconProp} color='#c4d3e0' />
                      <span className={styles.blogPostInfoTags}>
                        {tags.map(({ label, permalink: tagPermalink }) => (
                          <Tag label={label} permalink={tagPermalink} />
                        ))}
                      </span>
                    </>
                  )}
                  {readingTime && (
                    <>
                      <FontAwesomeIcon icon={faClock as IconProp} color='#c4d3e0' className='blog__readingTime' />
                      <span className={clsx(styles.blogPostReadTime, 'blog__readingTime')}>{readingTimePlural(readingTime)}</span>
                    </>
                  )}
                  {/* {truncatedPost && (
                    <div className={clsx('col text--right')}>
                      <Link
                        to={metadata.permalink}
                        aria-label={translate(
                          {
                            message: 'Read more about {title}',
                            id: 'theme.blog.post.readMoreLabel',
                            description: 'The ARIA label for the link to full blog posts from excerpts',
                          },
                          { title },
                        )}
                      >
                        <Translate id='theme.blog.post.readMore' description='The label used in blog post item excerpts to link to full blog posts'>
                          Read More
                        </Translate>
                        <FontAwesomeIcon icon={faArrowRight as IconProp} color='#c4d3e0' />
                      </Link>
                    </div>
                  )} */}
                </div>
              </>
            )}
            {/* 底部 */}
            {isBlogPostPage && (
              <footer className={clsx('row margin-top--lg', isBlogPostPage && styles.blogPostDetailsFull)}>
                {tagsExists && (
                  <div className={clsx('col', { 'col--9': truncatedPost })}>
                    <TagsListInline tags={tags} />
                  </div>
                )}
                {isBlogPostPage && editUrl && (
                  <div className='col margin-top--sm'>
                    <EditThisPage editUrl={editUrl} />
                  </div>
                )}
              </footer>
            )}
          </article>
        </div>
      </div>
    </StyledBlogItem>
  )
}
