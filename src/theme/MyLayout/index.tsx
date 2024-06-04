import { cn } from '@site/src/lib/utils'
import Layout from '@theme/Layout'
import type { Props } from '@theme/Layout'
import React from 'react'

export default function MyLayout({ children, maxWidth, ...layoutProps }: Props & { maxWidth?: number }): JSX.Element {
  return (
    <Layout {...layoutProps}>
      <div className="bg-[var(--content-background-color)">
        <div
          className={cn('mx-auto max-w-4xl px-4', 'margin-vert--lg')}
          style={maxWidth ? { maxWidth: `${maxWidth}px` } : {}}
        >
          <main>{children}</main>
        </div>
      </div>
    </Layout>
  )
}
