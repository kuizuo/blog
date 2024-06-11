import Link from '@docusaurus/Link'
import { translate } from '@docusaurus/Translate'
import { useBlogPost } from '@docusaurus/theme-common/internal'
import { Icon } from '@iconify/react'
import { cn } from '@site/src/lib/utils'
import type { Props } from '@theme/BlogSidebar/Desktop'
import React, { useState } from 'react'

import styles from './styles.module.css'

export default function BlogSidebarDesktop({ sidebar }: Props): JSX.Element {
  const { isBlogPostPage } = useBlogPost()
  const [isHovered, setIsHovered] = useState(false)

  const handleBack = () => {
    window.history.back()
  }

  return (
    <aside className="col col--2" onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
      <nav
        className={cn(styles.sidebar, 'thin-scrollbar')}
        aria-label={translate({
          id: 'theme.blog.sidebar.navAriaLabel',
          message: 'Blog recent posts navigation',
          description: 'The ARIA label for recent posts in the blog sidebar',
        })}
        style={{ opacity: isHovered ? 1 : 0 }}
      >
        {isBlogPostPage && (
          <div className={styles.backButton} onClick={handleBack}>
            <Icon icon="ri:arrow-go-back-line" />
          </div>
        )}

        <Link href="/blog" className={cn(styles.sidebarItemTitle, 'margin-bottom--sm')}>
          {sidebar.title}
        </Link>
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
    </aside>
  )
}
