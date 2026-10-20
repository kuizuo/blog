import { useThemeConfig } from '@docusaurus/theme-common'
import type { Props } from '@theme/DocSidebar/Desktop'
import CollapseButton from '@theme/DocSidebar/Desktop/CollapseButton'
import Content from '@theme/DocSidebar/Desktop/Content'
import clsx from 'clsx'
import { memo } from 'react'
import styles from './styles.module.css'

function DocSidebarDesktop({ path, sidebar, onCollapse, isHidden }: Props) {
  const { docs: { sidebar: { hideable } } } = useThemeConfig()

  return (
    <div className={clsx(styles.sidebar, isHidden && styles.sidebarHidden)}>
      {/* The transparent navbar already provides the site logo. */}
      <Content path={path} sidebar={sidebar} />
      {hideable && <CollapseButton onClick={onCollapse} />}
    </div>
  )
}

export default memo(DocSidebarDesktop)
