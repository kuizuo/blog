import ExecutionEnvironment from '@docusaurus/ExecutionEnvironment'
import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import useBrokenLinks from '@docusaurus/useBrokenLinks'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import { groupByProjects, projectTypeMap } from '@site/data/projects'
import collection from '@site/src/css/collection.module.css'
import { cn } from '@site/src/lib/utils'
import { upperFirst } from '@site/src/utils/jsUtils'
import Layout from '@theme/Layout'
import ShowcaseCard from './_components/ShowcaseCard'
import styles from './styles.module.css'

const TITLE = translate({ id: 'theme.project.title', message: '项目' })
const DESCRIPTION = translate({
  id: 'theme.project.description',
  message: '学而无用，不如学而用之。这里是我在技术领域中努力实践和应用的最佳证明。',
})

type ProjectState = {
  scrollTopPosition: number
  focusedElementId: string | undefined
}

export function prepareUserState(): ProjectState | undefined {
  if (ExecutionEnvironment.canUseDOM) {
    return {
      scrollTopPosition: window.scrollY,
      focusedElementId: document.activeElement?.id,
    }
  }
  return undefined
}

export default function Showcase(): JSX.Element {
  const { i18n } = useDocusaurusContext()
  const brokenLinks = useBrokenLinks()
  const groups = Object.entries(groupByProjects)
  const groupTitle = (key: string) => upperFirst(i18n.currentLocale === 'en' ? key : projectTypeMap[key])

  groups.forEach(([key]) => brokenLinks.collectAnchor(key))

  return (
    <Layout title={TITLE} description={DESCRIPTION}>
      <main className={collection.page}>
        <div className={collection.container}>
          <header className={collection.header}>
            <div>
              <h1 className={collection.title}>{TITLE}</h1>
              <p className={collection.description}>{DESCRIPTION}</p>
            </div>
            <Link href="https://github.com/kuizuo" className={collection.textLink}>
              <Translate id="project.github">在 GitHub 上查看</Translate>
              <span aria-hidden="true">↗</span>
            </Link>
          </header>
          <nav className={styles.categories} aria-label={translate({ id: 'project.categories', message: '项目分类' })}>
            {groups.map(([key, value]) => (
              <Link key={key} href={`#${key}`}>
                {groupTitle(key)}
                <span>{value.length}</span>
              </Link>
            ))}
          </nav>
          <div className={styles.groups}>
            {groups.map(([key, value]) => (
              <section key={key} id={key} className={styles.group} aria-labelledby={`heading-${key}`}>
                <div className={styles.groupHeader}>
                  <h2 id={`heading-${key}`}>{groupTitle(key)}</h2>
                  <span>{value.length}</span>
                </div>
                <div className={cn(styles.showcaseList, value.every(project => !project.preview) && styles.compactList)}>
                  {value.map(project => <ShowcaseCard key={project.title} project={project} />)}
                </div>
              </section>
            ))}
          </div>
        </div>
      </main>
    </Layout>
  )
}
