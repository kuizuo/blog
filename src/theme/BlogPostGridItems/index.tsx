import Link from '@docusaurus/Link'
import type { BlogPostFrontMatter } from '@docusaurus/plugin-content-blog'
import { cn } from '@site/src/lib/utils'
import Tag from '@site/src/theme/Tag'
import type { Props as BlogPostItemsProps } from '@theme/BlogPostItems'
import { AnimatePresence, motion } from 'framer-motion'
import { useState } from 'react'

import styles from './styles.module.css'

export default function BlogPostGridItems({ items }: BlogPostItemsProps): JSX.Element {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null)

  const data = items.map(({ content: BlogPostContent }) => {
    const { metadata, frontMatter } = BlogPostContent
    const { title, sticky } = frontMatter as BlogPostFrontMatter & { sticky: number }
    const { permalink, date, tags } = metadata
    const dateObj = new Date(date)
    const dateString = `${dateObj.getFullYear()}-${`0${dateObj.getMonth() + 1}`.slice(
      -2,
    )}-${`0${dateObj.getDate()}`.slice(-2)}`

    return {
      title,
      link: permalink,
      tags,
      date: dateString,
      sticky,
    }
  })

  return (
    <div className={cn('grid grid-cols-1 py-10 sm:grid-cols-2 lg:grid-cols-3')}>
      {data.map((item, idx) => (
        <div
          key={item.link}
          className="group relative block size-full p-2"
          onMouseEnter={() => setHoveredIndex(idx)}
          onMouseLeave={() => setHoveredIndex(null)}
        >
          <Link href={item.link} className="hover:no-underline">
            <AnimatePresence>
              {hoveredIndex === idx && (
                <motion.span
                  className="absolute inset-0 block size-full rounded-lg bg-neutral-100 dark:bg-slate-800/[0.8]"
                  layoutId="hoverBackground"
                  initial={{ opacity: 0 }}
                  animate={{
                    opacity: 1,
                    transition: { duration: 0.15 },
                  }}
                  exit={{
                    opacity: 0,
                    transition: { duration: 0.15, delay: 0.2 },
                  }}
                />
              )}
            </AnimatePresence>

            <Card className={cn('relative bg-blog', item.sticky && styles.blogSticky)}>
              <CardTitle className="transition duration-300 hover:text-primary">{item.title}</CardTitle>
              <CardFooter className="flex justify-between pt-4">
                <div
                  className={cn(styles.blogTags, 'inline-flex items-center gap-1 whitespace-nowrap text-sm text-text')}
                >
                  {item.tags?.length > 0 && (
                    <>
                      <svg width="1em" height="1em" viewBox="0 0 24 24">
                        <path
                          fill="currentColor"
                          fillRule="evenodd"
                          d="M10 15h4V9h-4v6Zm0 2v3a1 1 0 0 1-2 0v-3H5a1 1 0 0 1 0-2h3V9H5a1 1 0 1 1 0-2h3V4a1 1 0 1 1 2 0v3h4V4a1 1 0 0 1 2 0v3h3a1 1 0 0 1 0 2h-3v6h3a1 1 0 0 1 0 2h-3v3a1 1 0 0 1-2 0v-3h-4Z"
                        />
                      </svg>
                      {item.tags.slice(0, 2).map(({ label, permalink: tagPermalink, description }, index) => (
                        <>
                          {index !== 0 && '/'}
                          <Tag
                            label={label}
                            description={description}
                            permalink={tagPermalink}
                            key={tagPermalink}
                            className="tag"
                          />
                        </>
                      ))}
                    </>
                  )}
                </div>
                <div className="text-xs text-[var(--ifm-color-emphasis-600)]">{item.date}</div>
              </CardFooter>
            </Card>
          </Link>
        </div>
      ))}
    </div>
  )
}

export const Card = ({
  className,
  children,
}: {
  className?: string
  children: React.ReactNode
}) => {
  return (
    <div
      className={cn(
        'relative z-20 h-full w-full overflow-hidden rounded-lg border border-transparent bg-background p-4 group-hover:border-slate-700 dark:border-white/[0.2]',
        className,
      )}
    >
      <div className="relative z-50">
        <div className="p-2">{children}</div>
      </div>
    </div>
  )
}
export const CardTitle = ({
  className,
  children,
}: {
  className?: string
  children: React.ReactNode
}) => {
  return <h4 className={cn('text-text', className)}>{children}</h4>
}

export const CardFooter = ({
  className,
  children,
}: {
  className?: string
  children: React.ReactNode
}) => {
  return <div className={className}>{children}</div>
}
