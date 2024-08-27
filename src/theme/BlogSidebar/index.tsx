import { useWindowSize } from '@docusaurus/theme-common'
import type { Props } from '@theme/BlogSidebar'
import BlogSidebarDesktop from '@theme/BlogSidebar/Desktop'
import BlogSidebarMobile from '@theme/BlogSidebar/Mobile'

export default function BlogSidebar({ sidebar }: Props): JSX.Element | null {
  const windowSize = useWindowSize()
  if (!sidebar?.items.length) {
    return null
  }
  // Mobile sidebar doesn't need to be server-rendered
  if (windowSize === 'mobile') {
    return <BlogSidebarMobile sidebar={sidebar} />
  }
  return <BlogSidebarDesktop sidebar={sidebar} />
}
