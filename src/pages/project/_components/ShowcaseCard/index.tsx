import React, { memo, useEffect, useRef } from 'react'
import clsx from 'clsx'
import Image from '@theme/IdealImage'
import Link from '@docusaurus/Link'
import Translate from '@docusaurus/Translate'
import { useSpring, animated, to } from '@react-spring/web'

import styles from './styles.module.css'
import FavoriteIcon from '@site/src/components/svgIcons/FavoriteIcon'
import Tooltip from '../ShowcaseTooltip'
import {
  Tags,
  TagList,
  type TagType,
  type Project,
  type Tag,
} from '@site/data/project'
import { sortBy } from '@site/src/utils/jsUtils'
import { useGesture } from 'react-use-gesture'

const TagComp = React.forwardRef<HTMLLIElement, Tag>(
  ({ label, color, description }, ref) => (
    <li ref={ref} className={styles.tag} title={description}>
      <span className={styles.textLabel}>{label.toLowerCase()}</span>
      <span className={styles.colorLabel} style={{ backgroundColor: color }} />
    </li>
  ),
)

function ShowcaseCardTag({ tags }: { tags: TagType[] }) {
  const tagObjects = tags.map(tag => ({ tag, ...Tags[tag] }))

  // Keep same order for all tags
  const tagObjectsSorted = sortBy(tagObjects, tagObject =>
    TagList.indexOf(tagObject.tag),
  )

  return (
    <>
      {tagObjectsSorted.map((tagObject, index) => {
        const id = `showcase_card_tag_${tagObject.tag}`

        return (
          <Tooltip
            key={index}
            text={tagObject.description}
            anchorEl="#__docusaurus"
            id={id}
          >
            <TagComp key={index} {...tagObject} />
          </Tooltip>
        )
      })}
    </>
  )
}

const ShowcaseCard = memo(({ project }: { project: Project }) => {
  const domTarget = useRef(null)
  const [{ scale, zoom }, api] = useSpring(() => ({
    scale: 1,
    zoom: 0,
    config: {
      mass: 5,
      tension: 500,
      friction: 40,
    },
  }))

  useGesture(
    {
      onHover: ({ hovering }) =>
        hovering ? api({ scale: 1.05 }) : api({ scale: 1 }),
    },
    { domTarget, eventOptions: { passive: false } },
  )

  return (
    <animated.li
      ref={domTarget}
      style={{
        transform: 'perspective(100px)',
        scale: to([scale, zoom], (s, z) => s + z),
      }}
      key={project.title}
      className={clsx('card shadow--md', styles.showcaseCard)}
    >
      {project.preview && (
        <div className={clsx('card__image', styles.showcaseCardImage)}>
          <Image
            src={project.preview}
            alt={project.title}
            img={project.preview}
          />
        </div>
      )}
      <div className="card__body">
        <div className={clsx(styles.showcaseCardHeader)}>
          <h4 className={styles.showcaseCardTitle}>
            <Link href={project.website} className={styles.showcaseCardLink}>
              {project.title}
            </Link>
          </h4>
          {project.tags.includes('favorite') && (
            <FavoriteIcon svgClass={styles.svgIconFavorite} size="small" />
          )}
          {project.source && (
            <Link
              href={project.source}
              className={clsx(
                'button button--secondary button--sm',
                styles.showcaseCardSrcBtn,
              )}
            >
              <Translate id="showcase.card.sourceLink">源码</Translate>
            </Link>
          )}
        </div>
        <p className={styles.showcaseCardBody}>{project.description}</p>
      </div>
      <ul className={clsx('card__footer', styles.cardFooter)}>
        <ShowcaseCardTag tags={project.tags} />
      </ul>
    </animated.li>
  )
})

export default ShowcaseCard
