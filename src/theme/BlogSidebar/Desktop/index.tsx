import React from 'react'
import clsx from 'clsx'
import Link from '@docusaurus/Link'
import { Icon } from '@iconify/react'
import { translate } from '@docusaurus/Translate'
import { useBlogPost } from '@docusaurus/theme-common/internal'
import type { Props } from '@theme/BlogSidebar/Desktop'

import styles from './styles.module.scss'

export default function BlogSidebarDesktop({ sidebar }: Props): JSX.Element {
  const { isBlogPostPage } = useBlogPost()

  const handleBack = () => {
    window.history.back()
  }

  return (
    <aside className="col col--2">
      <nav
        className={clsx(styles.sidebar, 'thin-scrollbar')}
        aria-label={translate({
          id: 'theme.blog.sidebar.navAriaLabel',
          message: 'Blog recent posts navigation',
          description: 'The ARIA label for recent posts in the blog sidebar',
        })}
      >
        {isBlogPostPage && (
          <div className={styles.backButton} onClick={handleBack}>
            <Icon icon="ri:arrow-go-back-line"></Icon>
          </div>
        )}

        <Link
          href="/blog"
          className={clsx(styles.sidebarItemTitle, 'margin-bottom--sm')}
        >
          {sidebar.title}
        </Link>
        <ul className={clsx(styles.sidebarItemList, 'clean-list')}>
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
    </aside>
  )
}
