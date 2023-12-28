import React from 'react'
import clsx from 'clsx'
import { translate } from '@docusaurus/Translate'
import { usePluralForm } from '@docusaurus/theme-common'
import { useBlogPost } from '@docusaurus/theme-common/internal'
import type { Props } from '@theme/BlogPostItem/Header/Info'
import TagsListInline from '@theme/TagsListInline'

import styles from './styles.module.css'
import Tag from '@site/src/theme/Tag'
import { Icon } from '@iconify/react'

// Very simple pluralization: probably good enough for now
function useReadingTimePlural() {
  const { selectMessage } = usePluralForm()
  return (readingTimeFloat: number) => {
    const readingTime = Math.ceil(readingTimeFloat)
    return selectMessage(
      readingTime,
      translate(
        {
          id: 'theme.blog.post.readingTime.plurals',
          description:
            'Pluralized label for "{readingTime} min read". Use as much plural forms (separated by "|") as your language support (see https://www.unicode.org/cldr/cldr-aux/charts/34/supplemental/language_plural_rules.html)',
          message: 'One min read|{readingTime} min read',
        },
        { readingTime },
      ),
    )
  }
}

export function ReadingTime({ readingTime }: { readingTime: number }) {
  const readingTimePlural = useReadingTimePlural()
  return <>{readingTimePlural(readingTime)}</>
}

function Date({ date, formattedDate }: { date: string; formattedDate: string }) {
  return (
    <time dateTime={date} itemProp="datePublished">
      {formattedDate}
    </time>
  )
}

export default function BlogPostItemHeaderInfo({ className }: Props): JSX.Element {
  const { metadata } = useBlogPost()
  const { date, tags, formattedDate, readingTime } = metadata

  const tagsExists = tags.length > 0

  return (
    <div className={clsx(styles.container, 'margin-vert--sm', className)}>
      <div className={styles.date}>
        <Icon icon="ri:calendar-line" />
        <Date date={date} formattedDate={formattedDate} />
      </div>
      {tagsExists && (
        <div className={styles.tagInfo}>
          <Icon icon="ri:price-tag-3-line" />
          <div className={styles.tagList}>
            {tags.slice(0, 2).map(({ label, permalink: tagPermalink }, index) => {
              return (
                <div key={tagPermalink}>
                  {index !== 0 && '/'}
                  <Tag label={label} permalink={tagPermalink} className={'tag'} />
                </div>
              )
            })}
          </div>
        </div>
      )}
      {typeof readingTime !== 'undefined' && (
        <div className={styles.date}>
          <Icon icon="ri:time-line" />
          <ReadingTime readingTime={readingTime} />
        </div>
      )}
    </div>
  )
}
