import { Icon } from '@iconify/react'
import social from '@site/data/social'
import Tooltip from '@site/src/components/Tooltip'
import React from 'react'
import styles from './styles.module.css'

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
    <Tooltip key={title} text={title} anchorEl="#__docusaurus" id={`tooltip-${title}`}>
      <a href={href} target="_blank" {...prop} title={title}>
        {typeof icon === 'string' ? <Icon icon={icon} /> : icon}
      </a>
    </Tooltip>
  )
}

export default function SocialLinks({ ...prop }) {
  return (
    <div className={styles.socialLinks} {...prop}>
      {Object.entries(social)
        .filter(([_key, { href }]) => href)
        .map(([key, { href, icon, title, color }]) => {
          return <SocialLink key={key} href={href!} title={title} icon={icon} style={{ '--color': color }} />
        })}
    </div>
  )
}
