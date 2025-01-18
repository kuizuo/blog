import { groupBlogSidebarItemsByYear } from '@docusaurus/plugin-content-blog/client'
import { useThemeConfig } from '@docusaurus/theme-common'
import type { Props } from '@theme/BlogSidebar/Content'
import Heading from '@theme/Heading'
import React, { memo, type ReactNode } from 'react'

function BlogSidebarYearGroup({
  year,
  yearGroupHeadingClassName,
  children,
}: {
  year: string
  yearGroupHeadingClassName?: string
  children: ReactNode
}) {
  return (
    <div role="group">
      <Heading as="h3" className={yearGroupHeadingClassName}>
        {year}
      </Heading>
      {children}
    </div>
  )
}

function BlogSidebarContent({ items, yearGroupHeadingClassName, ListComponent }: Props): ReactNode {
  const themeConfig = useThemeConfig()
  if (themeConfig.blog.sidebar.groupByYear) {
    const itemsByYear = groupBlogSidebarItemsByYear(items)
    return (
      <>
        {itemsByYear.map(([year, yearItems]) => (
          <BlogSidebarYearGroup key={year} year={year} yearGroupHeadingClassName={yearGroupHeadingClassName}>
            <ListComponent items={yearItems} />
          </BlogSidebarYearGroup>
        ))}
      </>
    )
  }
  else {
    return <ListComponent items={items} />
  }
}

export default memo(BlogSidebarContent)
