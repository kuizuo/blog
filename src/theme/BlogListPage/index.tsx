import React from 'react'
import clsx from 'clsx'

import { PageMetadata, HtmlClassNameProvider, ThemeClassNames } from '@docusaurus/theme-common'
import Link from '@docusaurus/Link'
import Head from '@docusaurus/Head'
import Translate from '@docusaurus/Translate'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import Layout from '@theme/Layout'
import BlogPostItem from '@theme/BlogPostItem'
import BlogListPaginator from '@theme/BlogListPaginator'
import SearchMetadata from '@theme/SearchMetadata'
import type { Props } from '@theme/BlogListPage'
import Fade from 'react-reveal/Fade'

import ListFilter from '@site/static/icons/list.svg'
import CardFilter from '@site/static/icons/card.svg'
import { useViewType } from './useViewType'
import Hero from '@site/src/components/Hero'
import BlogInfo from '@site/src/components/BlogInfo'

function BlogListPageMetadata(props: Props): JSX.Element {
  const { metadata } = props
  const {
    siteConfig: { title: siteTitle },
  } = useDocusaurusContext()
  const { blogDescription, blogTitle, permalink } = metadata
  const isBlogOnlyMode = permalink === '/'
  const title = isBlogOnlyMode ? siteTitle : blogTitle
  return (
    <>
      <PageMetadata title={title} description={blogDescription} />
      <SearchMetadata tag='blog_posts_list' />
    </>
  )
}

function BlogListPageContent(props: Props) {
  const { metadata, items } = props

  const {
    siteConfig: { title: siteTitle },
  } = useDocusaurusContext()

  const isBlogOnlyMode = metadata.permalink === '/'
  const isPaginated = metadata.page > 1

  let description = `html, css, javascript, react, vue, node, typescript，前端开发，后端开发，技术分享，开源`

  const isBlogPage = metadata.permalink === '/'

  const { viewType, toggleViewType } = useViewType()

  const isCardView = viewType === 'card'
  const isListView = viewType === 'list'

  const showBlogInfo = false // 是否展示右侧博客作者信息

  return (
    <Layout description={description} wrapperClassName='blog-list__page'>
      <Head>
        <meta name='keywords' content='blog, javascript, js, typescript, node, react, vue, web, 前端, 后端' />
        <title>{siteTitle}</title>
      </Head>
      {!isPaginated && isBlogOnlyMode && <Hero />}
      <div className='container-wrapper'>
        <div className='container padding-vert--sm' style={!showBlogInfo ? { maxWidth: 1140 } : {}}>
          <div className='row'>
            <div className={'col col--12'}>
              {!isPaginated && (
                <h1 className='blog__section_title' id='homepage_blogs'>
                  <Translate description='latest blogs heading'>{!metadata.permalink.includes('essay') ? '最新博客' : '个人随笔'}</Translate>
                  &nbsp;
                  <svg width='31' height='31' viewBox='0 0 31 31' fill='none' xmlns='http://www.w3.org/2000/svg'>
                    <path
                      d='M25.8333 5.16666H5.16668C3.73293 5.16666 2.59626 6.31624 2.59626 7.74999L2.58334 23.25C2.58334 24.6837 3.73293 25.8333 5.16668 25.8333H25.8333C27.2671 25.8333 28.4167 24.6837 28.4167 23.25V7.74999C28.4167 6.31624 27.2671 5.16666 25.8333 5.16666ZM10.9792 19.375H9.42918L6.13543 14.8542V19.375H4.52084V11.625H6.13543L9.36459 16.1458V11.625H10.9792V19.375ZM17.4375 13.2525H14.2083V14.6992H17.4375V16.3267H14.2083V17.7604H17.4375V19.375H12.2708V11.625H17.4375V13.2525ZM26.4792 18.0833C26.4792 18.7937 25.8979 19.375 25.1875 19.375H20.0208C19.3104 19.375 18.7292 18.7937 18.7292 18.0833V11.625H20.3438V17.4504H21.8033V12.9037H23.4179V17.4375H24.8646V11.625H26.4792V18.0833Z'
                      className='newicon'
                    />
                  </svg>
                </h1>
              )}
              {/* switch list and card */}
              <div className='bloghome__swith-view'>
                <CardFilter onClick={() => toggleViewType('card')} className={viewType === 'card' ? 'bloghome__switch--selected' : 'bloghome__switch'} />
                <ListFilter onClick={() => toggleViewType('list')} className={viewType === 'list' ? 'bloghome__switch--selected' : 'bloghome__switch'} />
              </div>
            </div>
          </div>
          <div className='row'>
            <div className={isCardView && isBlogPage && showBlogInfo ? 'col col--9' : 'col col--12'}>
              <div className='bloghome__posts'>
                {isCardView && (
                  <div className='bloghome__posts-card'>
                    {items.map(({ content: BlogPostContent }, index) => (
                      <Fade key={BlogPostContent.metadata.permalink}>
                        <React.Fragment key={BlogPostContent.metadata.permalink}>
                          <BlogPostItem
                            key={BlogPostContent.metadata.permalink}
                            frontMatter={BlogPostContent.frontMatter}
                            assets={BlogPostContent.assets}
                            metadata={BlogPostContent.metadata}
                            truncated={BlogPostContent.metadata.truncated}
                          >
                            <BlogPostContent />
                          </BlogPostItem>
                        </React.Fragment>
                      </Fade>
                    ))}
                  </div>
                )}
                {isListView && (
                  <div className='bloghome__posts-list'>
                    {items.map(({ content: BlogPostContent }, index) => {
                      const { metadata: blogMetaData, frontMatter } = BlogPostContent
                      const { title } = frontMatter
                      const { permalink, date, tags } = blogMetaData
                      const dateObj = new Date(date)
                      const dateString = `${dateObj.getFullYear()}-${('0' + (dateObj.getMonth() + 1)).slice(-2)}-${('0' + dateObj.getDate()).slice(-2)}`

                      // const sticky = frontMatter.sticky
                      return (
                        <React.Fragment key={blogMetaData.permalink}>
                          <div className='post__list-item' key={blogMetaData.permalink}>
                            {/* {sticky && <div className={`post__list-stick iconfont`}></div>} */}
                            <Link to={permalink} className='post__list-title'>
                              {title}
                            </Link>
                            <div className='post__list-tags'>
                              {tags.length > 0 &&
                                tags.slice(0, 2).map(({ label, permalink: tagPermalink }, index) => (
                                  <Link
                                    key={tagPermalink}
                                    className={`post__tags ${index < tags.length ? 'margin-right--sm' : ''}`}
                                    to={tagPermalink}
                                    style={{
                                      fontSize: '0.75em',
                                      fontWeight: 500,
                                    }}
                                  >
                                    {label}
                                  </Link>
                                ))}
                            </div>
                            <div className='post__list-date'>{dateString}</div>
                          </div>
                        </React.Fragment>
                      )
                    })}
                  </div>
                )}
                <BlogListPaginator metadata={metadata} />
              </div>
            </div>
            {!isPaginated && isCardView && showBlogInfo && <BlogInfo />}
          </div>
        </div>
      </div>
    </Layout>
  )
}

export default function BlogListPage(props: Props): JSX.Element {
  return (
    <HtmlClassNameProvider className={clsx(ThemeClassNames.wrapper.blogPages, ThemeClassNames.page.blogListPage)}>
      <BlogListPageMetadata {...props} />
      <BlogListPageContent {...props} />
    </HtmlClassNameProvider>
  )
}
