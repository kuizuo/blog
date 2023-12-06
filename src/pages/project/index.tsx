import React from 'react'
import _ from 'loadsh'
import clsx from 'clsx'
import { translate } from '@docusaurus/Translate'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import ShowcaseCard from './_components/ShowcaseCard'
import { projects, groupByProjects, projectTypeMap } from '@site/data/project'

import ExecutionEnvironment from '@docusaurus/ExecutionEnvironment'

import styles from './styles.module.css'
import MyLayout from '@site/src/theme/MyLayout'

const TITLE = translate({
  id: 'theme.project.title',
  message: '项目',
})
const DESCRIPTION = translate({
  id: 'theme.project.description',
  message: '学而无用，不如学而用之。这里是我在技术领域中努力实践和应用的最佳证明。',
})

// const GITHUB_URL = 'https://github.com/kuizuo'

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

function ShowcaseHeader() {
  return (
    <section className="text--center">
      <h2>{TITLE}</h2>
      <p>{DESCRIPTION}</p>
      {/* <a
        className="button button--primary"
        href={GITHUB_URL}
        target="_blank"
        rel="noreferrer"
      >
        <Translate id="showcase.header.button">前往 Github 克隆项目</Translate>
      </a> */}
    </section>
  )
}

function ShowcaseCards() {
  const { i18n } = useDocusaurusContext()
  const lang = i18n.currentLocale

  if (projects.length === 0) {
    return (
      <section className="margin-top--lg margin-bottom--xl">
        <div className="container padding-vert--md text--center">
          <h2>No result</h2>
        </div>
      </section>
    )
  }

  return (
    <section className="margin-top--lg margin-bottom--xl">
      <>
        <div className="container margin-top--lg">
          <div className={clsx('margin-bottom--md', styles.showcaseFavoriteHeader)}></div>

          {Object.entries(groupByProjects).map(([key, value]) => {
            return (
              <div key={key}>
                <div className={clsx('margin-bottom--md', styles.showcaseFavoriteHeader)}>
                  <h3>{_.upperFirst(lang === 'en' ? key: projectTypeMap[key])}</h3>
                </div>
                <ul className={styles.showcaseList}>
                  {value.map(project => (
                    <ShowcaseCard key={project.title} project={project} />
                  ))}
                </ul>
              </div>
            )
          })}
        </div>
      </>
    </section>
  )
}

function Showcase(): JSX.Element {
  return (
    <MyLayout title={TITLE} description={DESCRIPTION} maxWidth={1280}>
      <main className="margin-vert--lg">
        <ShowcaseHeader />
        <ShowcaseCards />
      </main>
    </MyLayout>
  )
}

export default Showcase
