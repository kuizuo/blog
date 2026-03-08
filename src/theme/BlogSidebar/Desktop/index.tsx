import Link from '@docusaurus/Link'
import { translate } from '@docusaurus/Translate'
import { BlogSidebarItemList, useVisibleBlogSidebarItems } from '@docusaurus/plugin-content-blog/client'
import { Icon } from '@iconify/react'
import { cn } from '@site/src/lib/utils'
import type { Props as BlogSidebarContentProps } from '@theme/BlogSidebar/Content'
import BlogSidebarContent from '@theme/BlogSidebar/Content'
import type { Props } from '@theme/BlogSidebar/Desktop'
import clsx from 'clsx'
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

  const handleBack = () => {
    window.history.back()
  }

  const handleBackKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      handleBack()
    }
  }

  return (
    <aside className={cn('col col--2', styles.sidebarAside)}>
      <nav
        className={cn(styles.sidebar, 'thin-scrollbar')}
        aria-label={translate({
          id: 'theme.blog.sidebar.navAriaLabel',
          message: 'Blog recent posts navigation',
          description: 'The ARIA label for recent posts in the blog sidebar',
        })}
      >
        <div
          className={styles.backButton}
          onClick={handleBack}
          onKeyDown={handleBackKeyDown}
          role="button"
          tabIndex={0}
        >
          <Icon icon="ri:arrow-go-back-line" />
        </div>

        <Link href="/blog" className={cn(styles.sidebarItemTitle, styles.sidebarTitle)}>
          {sidebar.title}
        </Link>
        <div className={cn('margin-top--sm', styles.sidebarContent)}>
          <BlogSidebarContent
            items={items}
            ListComponent={ListComponent}
            yearGroupHeadingClassName={styles.yearGroupHeading}
          />
        </div>
      </nav>
    </aside>
  )
}
