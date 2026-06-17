import { useBlogPost } from '@docusaurus/plugin-content-blog/client'
import styles from './styles.module.css'

type FrontMatterWithSummary = {
  summary?: unknown
}

function getSummary(frontMatter: FrontMatterWithSummary): string | undefined {
  if (typeof frontMatter.summary !== 'string') {
    return undefined
  }

  const summary = frontMatter.summary.trim()
  return summary.length > 0 ? summary : undefined
}

export default function BlogPostItemSummary(): JSX.Element | null {
  const { frontMatter, isBlogPostPage } = useBlogPost()
  const summary = getSummary(frontMatter)

  if (!isBlogPostPage || !summary) {
    return null
  }

  return (
    <aside className={styles.summary} aria-labelledby="blog-post-summary-title">
      <div id="blog-post-summary-title" className={styles.title}>
        概要
      </div>
      <p className={styles.content}>{summary}</p>
    </aside>
  )
}
