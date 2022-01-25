import React, { useEffect } from 'react';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import BlogPostItem from '@theme/BlogPostItem';
import BlogListPaginator from '@theme/BlogListPaginator';
import BlogSidebar from '@theme/BlogSidebar';

import useViews from './useViews';
import styles from './styles.module.css';
import Fade from 'react-reveal/Fade';

import Translate from '@docusaurus/Translate';
import Head from '@docusaurus/Head';

import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTags, faHistory } from '@fortawesome/free-solid-svg-icons';
import ListFilter from './img/list.svg';
import CardFilter from './img/card.svg';

import Link from '@docusaurus/Link';
import { useViewType } from './useViewType';

import Hero from '@site/src/components/Hero';

function BlogListPage(props) {
  const { metadata, items, tags, sidebar } = props;
  const {
    siteConfig: { title: siteTitle },
  } = useDocusaurusContext();
  const isBlogOnlyMode = metadata.permalink === '/';
  const isPaginated = metadata.page > 1;

  let title = siteTitle + '';
  let suffix = '';
  let description = `html, css, javascript, react, vue, node, typescript，前端开发，后端开发，技术分享，开源`;

  const isBlogPage = metadata.permalink === '/';
  const views = useViews(items);
  const { viewType, toggleViewType } = useViewType();

  const isCardView = viewType === 'card';
  const isListView = viewType === 'list';

  const InfoCard = () => {
    function getCategoryOfTag(tag) {
      return tag[0].toUpperCase();
    }

    const tagCategories: { [category: string]: string[] } = {};
    Object.keys(tags).forEach((tag) => {
      const category = getCategoryOfTag(tag);
      tagCategories[category] = tagCategories[category] || [];
      tagCategories[category].push(tag);
    });

    const tagsList = Object.entries(tagCategories).sort(([a], [b]) => a.localeCompare(b));
    const tagsSection = tagsList
      .map(([category, tagsForCategory]) => (
        <div key={category} style={{ display: 'flex', flexWrap: 'wrap' }}>
          {tagsForCategory.map((tag, index) => (
            <Link className={`post__tags margin-right--sm margin-bottom--sm`} href={tags[tag].permalink} key={tag}>
              {tags[tag].name}({tags[tag].count})
            </Link>
          ))}
        </div>
      ))
      .filter((item) => item != null);

    const { totalCount: blogCount } = metadata;
    const tagCount = Object.values(tagCategories['/']).length;

    return (
      <div className={viewType === 'card' ? `col col--3 ${styles['info-wrapper']}` : ''} style={{ display: `${viewType === 'card' && isBlogPage ? '' : 'none'}` }}>
        <div className='bloghome__posts'>
          <div className={`bloghome__posts-card ${styles['info-wrapper']}`}>
            <div className={`row ${styles.card}`}>
              <div className={styles['personal-info-wrapper']}>
                <img className={styles['personal-img']} src='/img/logo.webp' alt='logo'></img>
                <h3 className={styles['personal-name']}>愧怍</h3>
                <h3 className={styles['personal-name']}>
                  文章数 {blogCount} | 标签数 {tagCount}
                </h3>
              </div>
            </div>
          </div>
          <div className={`bloghome__posts-card ${styles['info-wrapper']}`}>
            <div className={`row ${styles.card}`}>
              <div className={styles['personal-info-wrapper']}>
                <FontAwesomeIcon icon={faTags} color='#c4d3e0' />
                <Link className={`margin-horiz--sm`} href={'./tags'}>
                  标签
                </Link>
                <div className='margin-bottom--md'></div>
                <div>{tagsSection}</div>
              </div>
            </div>
          </div>
          {/* <div className={`bloghome__posts-card ${styles['info-wrapper']}`}>
            <div className={`row ${styles.card}`}>
              <div className={styles['personal-info-wrapper']}>
                <FontAwesomeIcon icon={faHistory} color='#c4d3e0' />
                <Link className={`post__tags margin-horiz--sm`} href={'./archive'}>
                  最新文章
                </Link>
                <div className='margin-bottom--md'></div>
                <BlogSidebar sidebar={sidebar} />
              </div>
            </div>
          </div> */}
        </div>
      </div>
    );
  };

  return (
    <Layout title={title} description={description} wrapperClassName='blog-list__page'>
      <Head>
        <meta name='keywords' content='blog, javascript, js, typescript, node, react, vue, web, 前端, 后端' />
        <title>{title + suffix}</title>
      </Head>
      {!isPaginated && isBlogOnlyMode && <Hero />}
      <div className='container-wrapper'>
        <div className='container padding-vert--sm'>
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
            <div className={viewType === 'card' && isBlogPage && tags ? 'col col--9' : 'col col--12'}>
              <div className='bloghome__posts'>
                {isCardView && (
                  <div className='bloghome__posts-card'>
                    {items.map(({ content: BlogPostContent }, index) => (
                      <Fade key={BlogPostContent.metadata.permalink}>
                        <React.Fragment key={BlogPostContent.metadata.permalink}>
                          <BlogPostItem
                            key={BlogPostContent.metadata.permalink}
                            frontMatter={BlogPostContent.frontMatter}
                            metadata={BlogPostContent.metadata}
                            truncated={BlogPostContent.metadata.truncated}
                            views={views.find((v) => v.title == BlogPostContent.frontMatter.title)?.views}
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
                      const { metadata: blogMetaData, frontMatter } = BlogPostContent;
                      const { title } = frontMatter;
                      const { permalink, date, tags } = blogMetaData;

                      const dateObj = new Date(date);

                      const year = dateObj.getFullYear();
                      let month = ('0' + (dateObj.getMonth() + 1)).slice(-2);
                      const day = ('0' + dateObj.getDate()).slice(-2);

                      const sticky = frontMatter.sticky;
                      return (
                        <React.Fragment key={blogMetaData.permalink}>
                          <div className='post__list-item' key={blogMetaData.permalink}>
                            {sticky && <div className={`post__list-stick iconfont`}></div>}
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
                            <div className='post__list-date'>
                              {year}-{month}-{day}
                            </div>
                          </div>
                        </React.Fragment>
                      );
                    })}
                  </div>
                )}
                <BlogListPaginator metadata={metadata} />
              </div>
            </div>
            {tags && <InfoCard />}
          </div>
        </div>
      </div>
    </Layout>
  );
}

export default BlogListPage;
