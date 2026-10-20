import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import { HtmlClassNameProvider, ThemeClassNames, translateTagsPageTitle } from '@docusaurus/theme-common'
import SegmentedControl from '@site/src/components/SegmentedControl'
import collection from '@site/src/css/collection.module.css'
import type { Props } from '@theme/BlogTagsListPage'
import Layout from '@theme/Layout'
import SearchMetadata from '@theme/SearchMetadata'
import { useRef, useState } from 'react'
import styles from './styles.module.css'

type TagItem = Props['tags'][number]
type TagView = 'all' | 'letters'

function compareLabels(left: string, right: string): number {
  const a = left.toLowerCase()
  const b = right.toLowerCase()
  return a < b ? -1 : a > b ? 1 : 0
}

function getGroup(label: string): string {
  const letter = label.charAt(0).toUpperCase()
  if (/^[A-Z]$/.test(letter)) return letter
  if (/^[\u3400-\u9fff]$/.test(letter)) return '中文'
  return '#'
}

function TagLinks({ tags }: { tags: readonly TagItem[] }) {
  return (
    <ul className={styles.tagList}>
      {tags.map(tag => (
        <li key={tag.permalink}>
          <Link
            to={tag.permalink}
            className={styles.tagLink}
            title={tag.description}
            aria-label={translate({ id: 'blog.tags.link', message: '查看「{tag}」的相关文章，共 {count} 篇' }, { tag: tag.label, count: tag.count })}
          >
            <span>{tag.label}</span>
            <span className={styles.tagCount} aria-hidden="true">{tag.count}</span>
          </Link>
        </li>
      ))}
    </ul>
  )
}

export default function BlogTagsListPage({ tags }: Props): JSX.Element {
  const title = translateTagsPageTitle()
  const description = translate({ id: 'blog.tags.description', message: '从一个关键词，找到感兴趣的内容。' })
  const [view, setView] = useState<TagView>('all')
  const [query, setQuery] = useState('')
  const search = useRef<HTMLInputElement>(null)
  const normalizedQuery = query.trim().toLowerCase()
  const filtered = tags.filter(tag => tag.label.toLowerCase().includes(normalizedQuery))
    .sort((left, right) => compareLabels(left.label, right.label))
  const groups = new Map<string, TagItem[]>()
  filtered.forEach((tag) => {
    const key = getGroup(tag.label)
    const group = groups.get(key) ?? []
    group.push(tag)
    groups.set(key, group)
  })

  return (
    <HtmlClassNameProvider className={`${ThemeClassNames.wrapper.blogPages} ${ThemeClassNames.page.blogTagsListPage}`}>
      <Layout title={title} description={description}>
        <SearchMetadata tag="blog_tags_list" />
        <main className={collection.page}>
          <div className={collection.container}>
            <header className={collection.header}>
              <div>
                <h1 className={collection.title}>{title}</h1>
                <p className={collection.description}>{description}</p>
              </div>
              <Link to="/blog" className={collection.textLink}>
                <span aria-hidden="true">←</span>
                <Translate id="blog.tags.back">返回博客</Translate>
              </Link>
            </header>
            <div className={styles.toolbar}>
              <div className={styles.search}>
                <label className="sr-only" htmlFor="blog-tag-search"><Translate id="blog.tags.search">搜索标签</Translate></label>
                <input ref={search} id="blog-tag-search" type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder={translate({ id: 'blog.tags.search.placeholder', message: '输入标签名称…' })} aria-controls="blog-tags" />
              </div>
              <p className={styles.result} role="status">
                <Translate id="blog.tags.count" values={{ count: filtered.length }}>{'{count} 个标签'}</Translate>
              </p>
              <SegmentedControl
                label={translate({ id: 'blog.tags.view', message: '标签显示方式' })}
                value={view}
                onChange={setView}
                controls="blog-tags"
                options={[
                  { value: 'all', label: <Translate id="blog.tags.all">全部标签</Translate> },
                  { value: 'letters', label: <Translate id="blog.tags.letters">按字母</Translate> },
                ]}
              />
            </div>
            <div id="blog-tags">
              {filtered.length === 0
                ? (
                    <div className={styles.empty}>
                      <h2><Translate id="blog.tags.empty">没有找到匹配的标签</Translate></h2>
                      <button
                        type="button"
                        onClick={() => {
                          setQuery('')
                          search.current?.focus()
                        }}
                      >
                        <Translate id="blog.tags.clear">清除搜索</Translate>
                      </button>
                    </div>
                  )
                : view === 'all'
                  ? <TagLinks tags={filtered} />
                  : (
                      <div className={styles.groups}>
                        {Array.from(groups, ([letter, group]) => (
                          <section key={letter} className={styles.group} aria-labelledby={`tag-group-${letter}`}>
                            <h2 id={`tag-group-${letter}`}>{letter === '中文' ? <Translate id="blog.tags.chinese">中文</Translate> : letter}</h2>
                            <TagLinks tags={group} />
                          </section>
                        ))}
                      </div>
                    )}
            </div>
          </div>
        </main>
      </Layout>
    </HtmlClassNameProvider>
  )
}
