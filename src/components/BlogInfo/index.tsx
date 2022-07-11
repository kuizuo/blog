import useGlobalData from '@docusaurus/useGlobalData'
import type { BlogTags, BlogPost } from '@docusaurus/plugin-content-blog'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faTag, faArchive, faBook, faThLarge } from '@fortawesome/free-solid-svg-icons'
import { IconProp } from '@fortawesome/fontawesome-svg-core'
import Link from '@docusaurus/Link'
import { SocialLinks } from '@site/src/components/Hero'

type Count = {
  blog: number
  tag: number
  doc: number
  project: number
}

export function BlogUser({ count, isNavbar = false }: { count?: Count; isNavbar?: boolean }) {
  if (!count) {
    const globalData = useGlobalData()
    const blogPluginData = globalData?.['docusaurus-plugin-content-blog']?.['default'] as any
    const blogData = blogPluginData?.blogs as BlogPost[]
    const tagData = blogPluginData?.tags as BlogTags
    const projectData = blogPluginData?.projects
    const docData = (globalData?.['docusaurus-plugin-content-docs']?.['default'] as any)?.versions[0].docs

    count = {
      blog: blogData.length,
      tag: Object.keys(tagData).length ?? 0,
      doc: docData?.length ?? 0,
      project: projectData?.length ?? 0,
    }
  }

  return (
    <div className={`row ${isNavbar ? 'bloginfo__card-navbar' : 'bloginfo__card'}`}>
      <Link href='/about'>
        <img className='bloginfo__img' src='/img/logo.webp' alt='logo'></img>
      </Link>
      <div>
        <Link className='bloginfo__name' href='about'>
          愧怍
        </Link>
      </div>
      <div className='bloginfo__description'>不是巅峰时的信仰，而是黄昏时的追逐</div>
      <div className='bloginfo__num'>
        <Link className='bloginfo__num-item' href='/archive' data-tips='博客数'>
          <FontAwesomeIcon icon={faArchive as IconProp} /> {count.blog}
        </Link>
        <Link className='bloginfo__num-item' href='/tags' data-tips='标签数'>
          <FontAwesomeIcon icon={faTag as IconProp} style={{ transform: 'rotate(90deg)' }} /> {count.tag}
        </Link>
        <Link className='bloginfo__num-item' href='/docs/skill' data-tips='笔记数'>
          <FontAwesomeIcon icon={faBook as IconProp} /> {count.doc}
        </Link>
        <Link className='bloginfo__num-item' href='/project' data-tips='项目数'>
          <FontAwesomeIcon icon={faThLarge as IconProp} /> {count.project}
        </Link>
      </div>
      <SocialLinks
        animatedProps={{
          maxWidth: '100%',
          padding: '0.5em 0',
          justifyContent: 'space-evenly',
          ...(isNavbar ? { borderBottom: '1px solid #eee' } : null),
        }}
      />
    </div>
  )
}

const TagsSection = ({ data }) => {
  return (
    <div className='bloginfo__tags'>
      {data
        .filter((tag) => tag != null)
        .map((tag) => (
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

const DocsSection = ({ data }) => {
  return (
    <div className='bloginfo__note'>
      {data
        .filter((doc) => (doc.id as string).includes('/category'))
        .map((doc) => (
          <Link className={`bloginfo__note-item`} href={doc.path} key={doc.id}>
            {(doc.id as string).replace('/category/', '')}
          </Link>
        ))}
    </div>
  )
}

export default function BlogInfo() {
  const globalData = useGlobalData()
  const blogPluginData = globalData?.['docusaurus-plugin-content-blog']?.['default'] as any
  const blogData = blogPluginData?.blogs as BlogPost[]
  const tagData = blogPluginData?.tags as BlogTags
  const docData = (globalData?.['docusaurus-plugin-content-docs']?.['default'] as any)?.versions[0].docs
  const projectData = globalData?.['docusaurus-plugin-content-project']?.['default'] as any

  const count: Count = {
    blog: blogData.length,
    tag: Object.keys(tagData).length ?? 0,
    doc: docData?.length ?? 0,
    project: projectData?.projects?.length ?? 0,
  }

  return (
    <div className={`col col--3 margin-bottom--md`}>
      <div className='bloghome__posts-card margin-bottom--md'>
        <BlogUser count={count} />
      </div>
      <div className='bloghome__posts-card margin-bottom--md'>
        <div className='row bloginfo__card'>
          <div>
            <FontAwesomeIcon icon={faTag as IconProp} color='#23affc' style={{ transform: 'rotate(90deg)' }} />
            <Link className='margin-horiz--sm' href='/tags'>
              标签
            </Link>
          </div>
          <TagsSection data={Object.values(tagData)} />
        </div>
      </div>
      <div className='bloghome__posts-card margin-bottom--md'>
        <div className='row bloginfo__card'>
          <div>
            <FontAwesomeIcon icon={faBook as IconProp} color='#23affc' />
            <Link className='margin-horiz--sm' href='/docs/skill'>
              笔记
            </Link>
          </div>
          <DocsSection data={docData} />
        </div>
      </div>
    </div>
  )
}
