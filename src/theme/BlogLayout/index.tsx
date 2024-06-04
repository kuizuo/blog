import BlogSidebar from '@theme/BlogSidebar'
import Layout from '@theme/Layout'
import clsx from 'clsx'
import React from 'react'

import type { Props } from '@theme/BlogLayout'

export default function BlogLayout(props: Props): JSX.Element {
  const { sidebar, toc, children, ...layoutProps } = props
  const hasSidebar = sidebar && sidebar.items.length > 0

  return (
    <Layout {...layoutProps}>
      <div className="margin-vert--md container">
        <div className="row">
          <BlogSidebar sidebar={sidebar} />
          <main
            className={clsx('col', {
              'col--8': hasSidebar,
              'col--8 col--offset-2': !hasSidebar,
            })}
            itemScope
            itemType="http://schema.org/Blog"
          >
            {children}
          </main>
          {toc && <div className="col col--2">{toc}</div>}
        </div>
      </div>
    </Layout>
  )
}
