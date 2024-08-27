import { useBlogPost } from '@docusaurus/plugin-content-blog/client'
import { cn } from '@site/src/lib/utils'
import type { Props } from '@theme/BlogPostItem'
import BlogPostItemContainer from '@theme/BlogPostItem/Container'
import BlogPostItemContent from '@theme/BlogPostItem/Content'
import BlogPostItemFooter from '@theme/BlogPostItem/Footer'
import BlogPostItemHeader from '@theme/BlogPostItem/Header'

// apply a bottom margin in list view
function useContainerClassName() {
  const { isBlogPostPage } = useBlogPost()
  return !isBlogPostPage ? 'group/blog rounded-md mt-0 bg-blog mb-8 shadow-blog' : ''
}

export default function BlogPostItem({ children, className }: Props): JSX.Element {
  const containerClassName = useContainerClassName()
  return (
    <BlogPostItemContainer className={cn(containerClassName, className)}>
      <BlogPostItemHeader />
      <BlogPostItemContent>{children}</BlogPostItemContent>
      <BlogPostItemFooter />
    </BlogPostItemContainer>
  )
}
