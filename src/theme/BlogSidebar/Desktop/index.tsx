import Link from '@docusaurus/Link'
import { translate } from '@docusaurus/Translate'
import { BlogSidebarItemList, useVisibleBlogSidebarItems } from '@docusaurus/plugin-content-blog/client'
import { Icon } from '@iconify/react'
import { cn } from '@site/src/lib/utils'
import type { Props as BlogSidebarContentProps } from '@theme/BlogSidebar/Content'
import BlogSidebarContent from '@theme/BlogSidebar/Content'
import type { Props } from '@theme/BlogSidebar/Desktop'
import clsx from 'clsx'
import { useState } from 'react'
import styles from './styles.module.css'

const ListComponent: BlogSidebarContentProps['ListComponent'] = ({ items }) => {
  return (
    <BlogSidebarItemList
      items={items}
      ulClassName={clsx(styles.sidebarItemList, 'clean-list')}
      liClassName={styles.sidebarItem}
      linkClassName={styles.sidebarItemLink}
      linkActiveClassName={styles.sidebarItemLinkActive}
    />
  )
}

export default function BlogSidebarDesktop({ sidebar }: Props): JSX.Element {
  const items = useVisibleBlogSidebarItems(sidebar.items)
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
        <div className={styles.backButton} onClick={handleBack}>
          <Icon icon="ri:arrow-go-back-line" />
        </div>

        <Link href="/blog" className={cn(styles.sidebarItemTitle, 'margin-bottom--sm')}>
          {sidebar.title}
        </Link>
        <BlogSidebarContent
          items={items}
          ListComponent={ListComponent}
          yearGroupHeadingClassName={styles.yearGroupHeading}
        />
      </nav>
    </aside>
  )
}
