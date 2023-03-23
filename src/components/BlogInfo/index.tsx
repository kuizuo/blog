import React from 'react'
import { usePluginData } from '@docusaurus/useGlobalData'
import type {
  BlogTag,
  BlogTags,
  BlogPost,
} from '@docusaurus/plugin-content-blog'
import Link from '@docusaurus/Link'
import { Icon } from '@iconify/react'
import { SocialLinks } from '@site/src/components/Hero'
import { useThemeConfig } from '@docusaurus/theme-common'
import useBaseUrl from '@docusaurus/useBaseUrl'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import { Fade } from 'react-awesome-reveal'
import { projects } from '@site/data/project'

type Count = {
  blog: number
  tag: number
  doc: number
  project: number
}

export function BlogUser({ isNavbar = false }: { isNavbar?: boolean }) {
  const {
    siteConfig: { tagline },
  } = useDocusaurusContext()
  const {
    navbar: { title, logo = { src: '' } },
  } = useThemeConfig()

  const logoLink = useBaseUrl(logo.src || '/')

  const blogPluginData = usePluginData('docusaurus-plugin-content-blog') as any
  const docData = (usePluginData('docusaurus-plugin-content-docs') as any)
    ?.versions[0].docs
  const blogData = blogPluginData?.blogs as BlogPost[]
  const tagData = blogPluginData?.tags as BlogTags

  const count: Count = {
    blog: blogData.length,
    tag: Object.keys(tagData).length ?? 0,
    doc: docData?.length ?? 0,
    project: projects?.length ?? 0,
  }

  return (
    <div
      className={`row ${isNavbar ? 'bloginfo__card-navbar' : 'bloginfo__card'}`}
    >
      <Link href="/about">
        <img className="bloginfo__img" src={logoLink} alt="logo"></img>
      </Link>
      <div>
        <Link className="bloginfo__name" href="about">
          {title}
        </Link>
      </div>
      <div className="bloginfo__description">{tagline}</div>
      <div className="bloginfo__num">
        <Link className="bloginfo__num-item" href="/archive">
          <Icon icon="carbon:blog" width="20" height="20" />
          {count.blog}
        </Link>
        <Link className="bloginfo__num-item" href="/tags">
          <Icon icon="ri:price-tag-3-line" width="20" height="20" />
          {count.tag}
        </Link>
        <Link className="bloginfo__num-item" href="/docs/skill">
          <Icon icon="carbon:notebook" width="20" height="20" />
          {count.doc}
        </Link>
        <Link
          className="bloginfo__num-item"
          href="/project"
          data-tips="project count"
        >
          <Icon icon="ph:projector-screen" width="20" height="20" />
          {count.project}
        </Link>
      </div>
      <SocialLinks
        style={{
          maxWidth: '100%',
          padding: '0.5em 0',
          justifyContent: 'space-evenly',
          ...(isNavbar ? { borderBottom: '1px solid #eee' } : null),
        }}
      />
    </div>
  )
}

const TagsSection = ({ data }: { data: BlogTag[] }) => {
  return (
    <div className="bloginfo__tags">
      {data
        .filter(tag => tag != null)
        .sort((a, b) => b.items.length - a.items.length)
        .slice(0, 25)
        .map(tag => (
          <Link
            className={`post__tags note__item margin-right--sm margin-bottom--sm`}
            href={tag.permalink}
            key={tag.permalink}
          >
            {tag.label}
          </Link>
        ))}
    </div>
  )
}

export default function BlogInfo() {
  const blogPluginData = usePluginData('docusaurus-plugin-content-blog') as any
  const tagData = blogPluginData?.tags as BlogTags

  return (
    <div className="bloginfo col col--3 margin-bottom--md">
      <section className="bloginfo__content">
        <Fade direction="up" triggerOnce={true}>
          <div className="bloghome__posts-card bloginfo__user margin-bottom--md">
            <BlogUser />
          </div>
          <div className="bloghome__posts-card margin-bottom--md">
            <div className="row bloginfo__card">
              <div style={{ display: 'inline-flex', alignItems: 'center' }}>
                <Icon icon="ri:price-tag-3-line" width="20" height="20" />
                <span className="margin-horiz--sm">标签</span>
              </div>
              <TagsSection data={Object.values(tagData)} />
            </div>
          </div>
        </Fade>
      </section>
    </div>
  )
}
