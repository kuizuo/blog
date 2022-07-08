import React, { memo } from 'react'
import clsx from 'clsx'
import Link from '@docusaurus/Link'

import styles from './styles.module.css'
import { type Website } from '@site/src/data/website'

const WebsiteCard = memo(({ website }: { website: Website }) => (
  <li key={website.name} className={clsx(styles.websiteCard, 'padding-vert--sm padding-horiz--md')}>
    <img src={typeof website.logo === 'string' ? website.logo : (website.logo as any).src.src} alt={website.name} className={clsx(styles.websiteCardImage)} />
    <div className={styles.websiteCardBody}>
      <div className={clsx(styles.websiteCardHeader)}>
        <h4 className={styles.websiteCardTitle}>
          <Link href={website.href} className={styles.websiteCardLink}>
            {website.name}
          </Link>
        </h4>
      </div>
      <p className={styles.websiteCardDesc} data-for="website-desc-tip" data-tip={website.desc}>
        {website.desc}
      </p>
    </div>
  </li>
))

export default WebsiteCard
