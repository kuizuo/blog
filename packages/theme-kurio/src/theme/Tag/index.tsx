import OriginalTag from '@theme-original/Tag'
import type { Props } from '@theme/Tag'
import React from 'react'

export default function Tag({ permalink, label, count, className }: Props & { className?: string }): JSX.Element {
  return <OriginalTag permalink={permalink} label={label} count={count} className={className} />
}
