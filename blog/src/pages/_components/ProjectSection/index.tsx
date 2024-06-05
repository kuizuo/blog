import React from 'react'
import clsx from 'clsx'
import Marquee from 'react-fast-marquee'
import { Project, projects } from '@site/data/projects'
import Translate from '@docusaurus/Translate'
import styles from './styles.module.scss'
import SectionTitle from '../SectionTitle'
import { useColorMode } from '@docusaurus/theme-common'

const removeHttp = (url: string) => {
  return url.replace(/(^\w+:|^)\/\//, '')
}

const showProjects = projects.filter(i => i.preview)

const Slider = ({ items }: { items: Project[] }) => {
  const { isDarkTheme } = useColorMode()

  return (
    <div className={styles.slider}>
      <Marquee
        pauseOnHover
        gradient
        gradientColor={!isDarkTheme ? '#f8fafc' : '#18181baa'}
        gradientWidth={100}
        className={styles.slideTrack}
      >
        {items.map((item, index) => {
          return (
            <div className={styles.slide} key={item.title}>
              <a href={item.website} target="_blank">
                <img src={item.preview} alt={item.title} className={styles.image} loading="lazy" />
                <div className={styles.slideBody}>
                  <h2 className={styles.title}>{item.title}</h2>
                  <p className={styles.website}>{removeHttp(item.website)}</p>
                </div>
              </a>
            </div>
          )
        })}
      </Marquee>
    </div>
  )
}

export default function ProjectSection() {
  return (
    <section className={clsx('container padding-vert--sm', styles.projectContainer)}>
      <SectionTitle icon={'ri:projector-line'} href={'/project'}>
        <Translate id="homepage.project.title">项目展示</Translate>
      </SectionTitle>
      <div className={styles.content}>
        <Slider items={showProjects}></Slider>
      </div>
    </section>
  )
}
