import { useBlogPost } from '@docusaurus/plugin-content-blog/client'
import { useBaseUrlUtils } from '@docusaurus/useBaseUrl'
import { cn } from '@site/src/lib/utils'
import type { Props } from '@theme/BlogPostItem/Container'

export default function BlogPostItemContainer({ children, className }: Props): JSX.Element {
  const { frontMatter, assets } = useBlogPost()
  const { withBaseUrl } = useBaseUrlUtils()
  const image = assets.image ?? frontMatter.image
  return (
    <article
      className={cn('relative px-4 pt-4 pb-3 lg:px-4', className)}
      itemProp="blogPost"
      itemScope
      itemType="http://schema.org/BlogPosting"
    >
      {image && (
        <>
          <meta itemProp="image" content={withBaseUrl(image, { absolute: true })} />
          <div className="z-1 absolute inset-0 h-[224px]">
            <div
              className="size-full rounded-[var(--ifm-pagination-nav-border-radius)] bg-cover bg-center bg-no-repeat"
              style={{
                WebkitMaskImage: 'linear-gradient(180deg, #fff -17.19%, #00000000 92.43%)',
                maskImage: 'linear-gradient(180deg, #fff -17.19%, #00000000 92.43%)',
                backgroundImage: `url("${image}")`,
              }}
            />
          </div>
          <div style={{ height: '120px' }} />
        </>
      )}
      {children}
    </article>
  )
}
