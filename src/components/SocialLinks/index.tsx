import React from 'react'
import { useThemeConfig } from '@docusaurus/theme-common'
import { ThemeConfig } from '@docusaurus/preset-classic'
import { Icon } from '@iconify/react'
import JuejinIcon from '@site/static/svg/juejin.svg'

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

function SocialLink({
  href,
  icon,
  title,
  ...prop
}: {
  href: string
  title: string
  icon: string | JSX.Element
}) {
  return (
    <a href={href} target="_blank" {...prop} title={title}>
      {typeof icon === 'string' ? <Icon icon={icon} /> : icon}
    </a>
  )
}

export default function SocialLinks({ ...prop }) {
  const themeConfig = useThemeConfig() as ThemeConfig & { socials: Social }

  const socials = themeConfig.socials

  return (
    <div className={styles.social__links} {...prop}>
      {socials.github && <SocialLink href={socials.github} title="gitub" icon="ri:github-line" />}
      {socials.juejin && <SocialLink href={socials.juejin} title="掘金" icon={<JuejinIcon />} />}
      {socials.twitter && <SocialLink href={socials.twitter} title="X" icon="ri:twitter-x-line" />}
      {socials.qq && <SocialLink href={socials.qq} title="QQ" icon="ri:qq-line" />}
      {socials.zhihu && <SocialLink href={socials.zhihu} title="知乎" icon="ri:zhihu-line" />}
      {socials.email && <SocialLink href={socials.email} title="Email" icon="ri:mail-line" />}
      {socials.cloudmusic && (
        <SocialLink href={socials.cloudmusic} title="Music" icon="ri:netease-cloud-music-line" />
      )}
      <SocialLink href="/blog/rss.xml" title="Rss" icon="ri:rss-line" />
    </div>
  )
}
