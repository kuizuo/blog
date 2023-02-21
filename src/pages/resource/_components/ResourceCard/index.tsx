import React, { memo } from 'react'
import clsx from 'clsx'
import Link from '@docusaurus/Link'

import styles from './styles.module.css'
import { type Resource } from '@site/data/resource'
import Tooltip from '../../../project/_components/ShowcaseTooltip'

const ResourceCard = memo(({ resource }: { resource: Resource }) => (
  <li
    key={resource.name}
    className={clsx(styles.resourceCard, 'padding-vert--sm padding-horiz--md')}
  >
    <img
      src={
        typeof resource.logo === 'string'
          ? resource.logo
          : (resource.logo as any)?.src?.src
      }
      alt={resource.name}
      className={clsx(styles.resourceCardImage)}
    />
    <div className={styles.resourceCardBody}>
      <div className={clsx(styles.resourceCardHeader)}>
        <h4 className={styles.resourceCardTitle}>
          <Link href={resource.href} className={styles.resourceCardLink}>
            {resource.name}
          </Link>
        </h4>
      </div>
      <Tooltip
        key={resource.name}
        text={resource.desc}
        anchorEl="#__docusaurus"
        id={`tooltip-${resource.name}`}
      >
        <p className={styles.resourceCardDesc}>{resource.desc}</p>
      </Tooltip>
    </div>
  </li>
))

export default ResourceCard
