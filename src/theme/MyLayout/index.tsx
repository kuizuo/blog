import React from 'react'
import clsx from 'clsx'
import Layout from '@theme/Layout'
import type { Props } from '@theme/Layout'

import styles from './styles.module.scss'

export default function MyLayout({
  children,
  ...layoutProps
}: Props): JSX.Element {
  return (
    <Layout {...layoutProps}>
      <div className={styles.containerWrapper}>
        <div className={clsx(styles.myContainer, 'margin-vert--lg')}>
          <main>{children}</main>
        </div>
      </div>
    </Layout>
  )
}
