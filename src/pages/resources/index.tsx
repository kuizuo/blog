import Link from '@docusaurus/Link'
import { HtmlClassNameProvider, PageMetadata, ThemeClassNames } from '@docusaurus/theme-common'
import { resourceData } from '@site/data/resources'
import { cn } from '@site/src/lib/utils'
import BackToTopButton from '@theme/BackToTopButton'
import Layout from '@theme/Layout'
import React from 'react'
import ResourceCard from './_components/ResourceCard'
import styles from './resource.module.css'

function CategorySidebar() {
  const sidebar = {
    title: '',
    items: resourceData.map(w => ({ title: w.name, permalink: `#${w.name}` })),
  }

  return (
    <nav className={cn(styles.sidebar, 'thin-scrollbar')}>
      <div className={cn(styles.sidebarItemTitle, 'margin-bottom--md')}>{sidebar.title}</div>
      <ul className={cn(styles.sidebarItemList, 'clean-list')}>
        {sidebar.items.map(item => (
          <li key={item.permalink} className={styles.sidebarItem}>
            <Link
              isNavLink
              to={item.permalink}
              className={styles.sidebarItemLink}
              activeClassName={styles.sidebarItemLinkActive}
            >
              {item.title}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  )
}

function CategoryList() {
  return (
    <div className={styles.category}>
      {resourceData.map(cate => (
        <div key={cate.name}>
          <div className={styles.cateHeader}>
            <h2 id={cate.name} className="anchor">
              <a className="hash-link" href={`#${cate.name}`} title={cate.name}>
                {cate.name}
              </a>
            </h2>
          </div>
          <section>
            <ul className={styles.resourceList}>
              {cate.resources.map(resource => (
                <ResourceCard key={resource.name} resource={resource} />
              ))}
            </ul>
          </section>
        </div>
      ))}
    </div>
  )
}

export default function Resources() {
  const title = '网址导航'
  const description = '整合日常开发常用，推荐的网站导航页'

  return (
    <HtmlClassNameProvider className={cn(ThemeClassNames.wrapper.blogPages, ThemeClassNames.page.blogTagsListPage)}>
      <PageMetadata title={title} description={description} />
      <Layout>
        <div className="margin-top--md container">
          <div className="row">
            <aside className={cn('col col--2')}>
              <CategorySidebar />
            </aside>
            <main className="col col--10">
              <CategoryList />
            </main>
          </div>
        </div>
        <BackToTopButton />
      </Layout>
    </HtmlClassNameProvider>
  )
}
