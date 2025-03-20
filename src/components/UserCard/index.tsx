import Link from '@docusaurus/Link'
import type { BlogPost } from '@docusaurus/plugin-content-blog'
import { useThemeConfig } from '@docusaurus/theme-common'
import useBaseUrl from '@docusaurus/useBaseUrl'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import { usePluginData } from '@docusaurus/useGlobalData'
import { Icon } from '@iconify/react'
import SocialLinks from '@site/src/components/SocialLinks'
import { cn } from '@site/src/lib/utils'

import { projects } from '@site/data/projects'

import styles from './styles.module.css'

type Count = {
  blog: number
  tag: number
  doc: number
  project: number
}

export default function UserCard({ isNavbar = false }: { isNavbar?: boolean }) {
  const {
    siteConfig: { customFields },
  } = useDocusaurusContext()
  const { bio } = customFields as { bio: string }

  const {
    navbar: { title, logo = { src: '' } },
  } = useThemeConfig()

  const logoLink = useBaseUrl(logo.src || '/')

  const blogData = usePluginData('docusaurus-plugin-content-blog') as {
    posts: BlogPost[]
    postNum: number
    tagNum: number
  }
  const docData = (
    usePluginData('docusaurus-plugin-content-docs') as {
      versions: { docs: BlogPost[] }
    }
  )?.versions[0].docs

  const count: Count = {
    blog: blogData.postNum,
    tag: blogData.tagNum ?? 0,
    doc: docData?.length ?? 0,
    project: projects?.length ?? 0,
  }

  return (
    <div className={cn(isNavbar ? styles.userCardNavbar : styles.userCard)}>
      <Link href="/about">
        <img className={styles.cardImg} src={logoLink} alt="logo" />
      </Link>
      <div>
        <Link className={styles.name} href="about">
          {title}
        </Link>
      </div>
      <div className={styles.bio}>{bio}</div>
      <div className={styles.num}>
        <Link className={styles.numItem} href="/blog/archive">
          <Icon icon="carbon:blog" width="20" height="20" />
          {count.blog}
        </Link>
        <Link className={styles.numItem} href="/blog/tags">
          <Icon icon="ri:price-tag-3-line" width="20" height="20" />
          {count.tag}
        </Link>
        <Link className={styles.numItem} href="/project" data-tips="project count">
          <Icon icon="ph:projector-screen" width="20" height="20" />
          {count.project}
        </Link>
      </div>
      <SocialLinks
        style={{
          maxWidth: '100%',
          padding: '0.5em 0',
          justifyContent: 'center',
          gap: '0.5rem',
          ...(isNavbar ? { borderBottom: '1px solid var(--ifm-border-color)' } : null),
        }}
      />
    </div>
  )
}
