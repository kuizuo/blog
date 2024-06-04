import Layout from '@theme/Layout'
import type { Props } from '@theme/Layout'
import clsx from 'clsx'
import React from 'react'

export default function MyLayout({ children, maxWidth, ...layoutProps }: Props & { maxWidth?: number }): JSX.Element {
  return (
    <Layout {...layoutProps}>
      <div className="bg-[var(--content-background-color)">
        <div
          className={clsx('mx-auto max-w-4xl px-4', 'margin-vert--lg')}
          style={maxWidth ? { maxWidth: `${maxWidth}px` } : {}}
        >
          <main>{children}</main>
        </div>
      </div>
    </Layout>
  )
}
