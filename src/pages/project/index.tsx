import { translate } from '@docusaurus/Translate'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import { groupByProjects, projectTypeMap, projects } from '@site/data/projects'
import { cn } from '@site/src/lib/utils'
import ShowcaseCard from './_components/ShowcaseCard'

import ExecutionEnvironment from '@docusaurus/ExecutionEnvironment'

import { MagicContainer } from '@site/src/components/magicui/magic-card'
import MyLayout from '@site/src/theme/MyLayout'
import { upperFirst } from '@site/src/utils/jsUtils'
import styles from './styles.module.css'
import React from 'react'

const TITLE = translate({
  id: 'theme.project.title',
  message: 'Projetos',
})
const DESCRIPTION = translate({
  id: 'theme.project.description',
  message: 'Código, criatividade e muita tentativa e erro. Seja bem-vindo(a) aos meus projetos!" 🎨💻🫡',
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

function ShowcaseHeader() {
  return (
    <section className="text-center">
      <h2>{TITLE}</h2>
      <p>{DESCRIPTION}</p>
      {}
    </section>
  )
}

function ShowcaseCards() {
  const { i18n } = useDocusaurusContext()
  const lang = i18n.currentLocale

  if (projects.length === 0) {
    return (
      <section className="margin-top--lg margin-bottom--xl">
        <div className="padding-vert--md container text-center">
          <h2>Sem projetos</h2>
        </div>
      </section>
    )
  }

  return (
    <section className="margin-top--lg margin-bottom--xl">
      <>
        <div className="margin-top--lg container">
          <div className={cn('my-4', styles.showcaseFavoriteHeader)} />
          {Object.entries(groupByProjects).map(([key, value]) => {
            return (
              <div key={key}>
                <div className={cn('my-4', styles.showcaseFavoriteHeader)}>
                  <h3>{upperFirst(lang === 'en' ? key : projectTypeMap[key])}</h3>
                </div>
                <MagicContainer className={styles.showcaseList}>
                  {value.map(project => (
                    <ShowcaseCard key={project.title} project={project} />
                  ))}
                </MagicContainer>
              </div>
            )
          })}
          <MagicContainer />
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
