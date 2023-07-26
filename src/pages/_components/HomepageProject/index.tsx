import React from 'react'
import clsx from 'clsx'
import { Project, projects } from '@site/data/project'
import { Icon } from '@iconify/react'
import Translate from '@docusaurus/Translate'
import Link from '@docusaurus/Link'
import styles from './styles.module.scss'

const removeHttps = (url: string) => {
  return url.replace(/(^\w+:|^)\/\//, '')
}

const Slider = ({ items }: { items: Project[] }) => {
  return (
    <div className={styles.slider}>
      <div className={styles['slide-track']}>
        {items
          .filter(i => i.preview)
          .map((item, index) => {
            return (
              <div className={styles.slide}>
                <a href={item.website} target="_blank">
                  <img
                    src={item.preview}
                    alt={item.title}
                    className={styles.image}
                    loading="lazy"
                  />
                  <div className={styles.slideBody}>
                    <h2 className={styles.title}>{item.title}</h2>
                    <p className={styles.website}>
                      {removeHttps(item.website)}
                    </p>
                  </div>
                </a>
              </div>
            )
          })}
      </div>
    </div>
  )
}
const HomepageProject = () => {
  return (
    <>
      <div
        className={clsx('container padding-vert--sm', styles.projectContainer)}
      >
        <div className={styles.projectTitle}>
          <h2>
            <Icon icon="ri:projector-line"></Icon>
            <Translate id="theme.blog.title">一些项目</Translate>
          </h2>
          <Link href="/project" className={styles.moreButton}>
            查看更多
            <Icon icon="ri:arrow-right-s-line"></Icon>
          </Link>
        </div>
        <div style={{ position: 'relative' }}>
          <div style={{ overflow: 'hidden' }}>
            <Slider items={projects}></Slider>
          </div>
          <div className={clsx(styles.gradientBox, styles.leftBox)} />
          <div className={clsx(styles.gradientBox, styles.rightBox)} />
        </div>
      </div>
    </>
  )
}

export default HomepageProject
