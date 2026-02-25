import { useBlogPost } from '@docusaurus/plugin-content-blog/client'
import BlogPostItemHeaderInfo from '@theme/BlogPostItem/Header/Info'
import BlogPostItemHeaderTitle from '@theme/BlogPostItem/Header/Title'

export default function BlogPostItemHeader(): JSX.Element {
  const { isBlogPostPage } = useBlogPost()
  return (
    <header style={{ position: 'relative', zIndex: 2 }}>
      <BlogPostItemHeaderTitle />
      {isBlogPostPage && (
        <>
          <BlogPostItemHeaderInfo />
          {/* <BlogPostItemHeaderAuthors /> */}
        </>
      )}
    </header>
  )
}
