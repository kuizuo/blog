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
import BackToTopButton from '@theme/BackToTopButton'
//@ts-ignore
import Fade from 'react-reveal/Fade'

import CardFilter from '@site/static/icons/card.svg'
import ListFilter from '@site/static/icons/list.svg'
import GridFilter from '@site/static/icons/grid.svg'
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
  const isGridView = viewType === 'grid'

  return (
    <Layout description={description} wrapperClassName='blog-list__page'>
      <Head>
        <meta
          name='keywords'
          content='blog, javascript, js, typescript, node, react, vue, web, 前端, 后端'
        />
        <title>{siteTitle}</title>
      </Head>
      {!isPaginated && isBlogOnlyMode && <Hero />}
      <BackToTopButton />

      <div className='container-wrapper'>
        <div className='container padding-vert--sm' style={!isCardView ? { maxWidth: 1140 } : {}}>
          <div className='row'>
            <div className={'col col--12'}>
              {!isPaginated && (
                <h1 className='blog__section_title' id='homepage_blogs'>
                  <Translate description='latest blogs heading'>
                    {!metadata.permalink.includes('essay') ? '最新博客' : '个人随笔'}
                  </Translate>
                </h1>
              )}
              <div className='bloghome__swith-view'>
                <ListFilter
                  onClick={() => toggleViewType('list')}
                  className={
                    viewType === 'list' ? 'bloghome__switch--selected' : 'bloghome__switch'
                  }
                />
                <GridFilter
                  onClick={() => toggleViewType('grid')}
                  className={
                    viewType === 'grid' ? 'bloghome__switch--selected' : 'bloghome__switch'
                  }
                />
                <CardFilter
                  onClick={() => toggleViewType('card')}
                  className={
                    viewType === 'card' ? 'bloghome__switch--selected' : 'bloghome__switch'
                  }
                />
              </div>
            </div>
          </div>
          <div className='row'>
            <div className={isCardView ? 'col col--9' : 'col col--12'}>
              <div className='bloghome__posts'>
                {(isListView || isCardView) && (
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
                {isGridView && (
                  <div className='bloghome__posts-list'>
                    {items.map(({ content: BlogPostContent }, index) => {
                      const { metadata: blogMetaData, frontMatter } = BlogPostContent
                      const { title } = frontMatter
                      const { permalink, date, tags } = blogMetaData
                      const dateObj = new Date(date)
                      const dateString = `${dateObj.getFullYear()}-${(
                        '0' +
                        (dateObj.getMonth() + 1)
                      ).slice(-2)}-${('0' + dateObj.getDate()).slice(-2)}`

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
                                tags
                                  .slice(0, 2)
                                  .map(({ label, permalink: tagPermalink }, index) => (
                                    <Link
                                      key={tagPermalink}
                                      className={`post__tags ${
                                        index < tags.length ? 'margin-right--sm' : ''
                                      }`}
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
            {isCardView && <BlogInfo />}
          </div>
        </div>
      </div>
    </Layout>
  )
}

export default function BlogListPage(props: Props): JSX.Element {
  return (
    <HtmlClassNameProvider
      className={clsx(ThemeClassNames.wrapper.blogPages, ThemeClassNames.page.blogListPage)}
    >
      <BlogListPageMetadata {...props} />
      <BlogListPageContent {...props} />
    </HtmlClassNameProvider>
  )
}
