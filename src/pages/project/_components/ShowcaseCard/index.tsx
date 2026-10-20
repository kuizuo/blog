import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import { type Project, TagList, Tags } from '@site/data/projects'
import { memo } from 'react'
import styles from './styles.module.css'

const ShowcaseCard = memo(({ project }: { project: Project }) => (
  <article className={styles.card}>
    {project.preview && (
      <div className={styles.preview}>
        <span aria-hidden="true">{project.title}</span>
        <img
          src={project.preview}
          alt={project.title}
          loading="lazy"
          decoding="async"
          onError={(event) => { event.currentTarget.hidden = true }}
        />
      </div>
    )}
    <div className={styles.body}>
      <h3 className={styles.title}>
        <Link href={project.website}>{project.title}</Link>
        <span className={styles.arrow} aria-hidden="true">↗</span>
      </h3>
      <p className={styles.description}>{project.description}</p>
      <div className={styles.footer}>
        <ul className={styles.tags}>
          {TagList.filter(tag => project.tags.includes(tag)).map(tag => (
            <li key={tag} className={styles.tag} title={Tags[tag].description}>
              <span className={styles.dot} style={{ backgroundColor: Tags[tag].color }} />
              {translate({ id: `project.tag.${tag}`, message: Tags[tag].label })}
            </li>
          ))}
        </ul>
        {project.source && (
          <Link
            href={project.source}
            className={styles.source}
            aria-label={translate({ id: 'project.source', message: '查看 {title} 的源码' }, { title: project.title })}
          >
            <Translate id="showcase.card.sourceLink">源码</Translate>
            <span aria-hidden="true">↗</span>
          </Link>
        )}
      </div>
    </div>
  </article>
))

export default ShowcaseCard
