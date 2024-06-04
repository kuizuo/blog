import Link from '@docusaurus/Link'
import { cn } from '@site/src/lib/utils'
import type { Props } from '@theme/Tag'
import React from 'react'

import styles from './styles.module.css'

export default function Tag({ permalink, label, count, className }: Props & { className?: string }): JSX.Element {
  return (
    <Link href={permalink} className={cn(styles.tag, count ? styles.tagWithCount : styles.tagRegular, className)}>
      {label}
      {count && <span>{count}</span>}
    </Link>
  )
}
