import React from 'react'
import { useThemeConfig } from '@docusaurus/theme-common'
import { ThemeConfig } from '@docusaurus/preset-classic'
import { Icon } from '@iconify/react'

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
  const themeConfig = useThemeConfig() as ThemeConfig & { socials: Social }

  const socials = themeConfig.socials

  const map = {
    github: {
      href: socials.github,
      title: 'GitHub',
      icon: 'ri:github-line',
      color: '#010409',
    },
    juejin: {
      href: socials.juejin,
      title: '掘金',
      icon: 'simple-icons:juejin',
      color: '#1E81FF',
    },
    twitter: {
      href: socials.twitter,
      title: 'Twitter',
      icon: 'ri:twitter-line',
      color: '#1da1f2',
    },
    qq: {
      href: socials.qq,
      title: 'QQ',
      icon: 'ri:qq-line',
      color: '#1296db',
    },
    wx: {
      href: socials.wx,
      title: '微信',
      icon: 'ri:wechat-2-line',
      color: '#07c160',
    },
    zhihu: {
      href: socials.zhihu,
      title: '知乎',
      icon: 'ri:zhihu-line',
      color: '#1772F6',
    },
    email: {
      href: socials.email,
      title: '邮箱',
      icon: 'ri:mail-line',
      color: '#D44638',
    },
    cloudmusic: {
      href: socials.cloudmusic,
      title: '网易云',
      icon: 'ri:netease-cloud-music-line',
      color: '#C20C0C',
    },
    rss: {
      href: '/blog/rss.xml',
      title: 'RSS',
      icon: 'ri:rss-line',
      color: '#FFA501',
    },
  }

  return (
    <div className={styles.socialLinks} {...prop}>
      {Object.entries(map).map(([key, { href, icon, title, color }]) => {
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
