import React from 'react'
import { useViewType } from '@site/src/hooks/useViewType'
import { Icon } from '@iconify/react'

import styles from './styles.module.scss'

export default function ViewTypeSwitch(): JSX.Element {
  const { viewType, toggleViewType } = useViewType()

  return (
    <div className={styles.blogSwithView}>
      <Icon
        icon="ph:list"
        width="24"
        height="24"
        onClick={() => toggleViewType('list')}
        color={viewType === 'list' ? 'var(--ifm-color-primary)' : '#ccc'}
      />
      <Icon
        icon="ph:grid-four"
        width="24"
        height="24"
        onClick={() => toggleViewType('grid')}
        color={viewType === 'grid' ? 'var(--ifm-color-primary)' : '#ccc'}
      />
    </div>
  )
}
