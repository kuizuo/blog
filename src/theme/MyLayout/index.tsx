import React from 'react'
import clsx from 'clsx'
import Layout from '@theme/Layout'

import styles from './styles.module.scss'

export default function MyLayout({
  children,
}: {
  children: React.ReactNode
}): JSX.Element {
  return (
    <Layout>
      <div className={clsx(styles.myContainer, 'margin-vert--lg')}>
        <main itemScope itemType="http://schema.org/Blog">
          {children}
        </main>
      </div>
    </Layout>
  )
}
