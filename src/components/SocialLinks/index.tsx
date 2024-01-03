import React from 'react'
import { useThemeConfig } from '@docusaurus/theme-common'
import { ThemeConfig } from '@docusaurus/preset-classic'
import { Icon } from '@iconify/react'
import social from '@site/data/social'
import styles from './styles.module.scss'

export type Social = {
  github?: string
  twitter?: string
  juejin?: string
  csdn?: string
  qq?: string
  wx?: string
  cloudmusic?: string
  zhihu?: string
  email?: string
}

interface Props {
  href: string
  title: string
  color?: string
  icon: string | JSX.Element
  [key: string]: unknown
}

function SocialLink({ href, icon, title, color, ...prop }: Props) {
  return (
    <a href={href} target="_blank" {...prop} title={title}>
      {typeof icon === 'string' ? <Icon icon={icon} /> : icon}
    </a>
  )
}

export default function SocialLinks({ ...prop }) {
  return (
    <div className={styles.socialLinks} {...prop}>
      {Object.entries(social).map(([key, { href, icon, title, color }]) => {
        if (!href) return <></>

        return (
          <SocialLink
            key={key}
            href={href}
            title={title}
            icon={icon}
            style={{ '--color': color }}
          ></SocialLink>
        )
      })}
    </div>
  )
}
