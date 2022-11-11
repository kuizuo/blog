import React, { memo } from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';

import styles from './styles.module.css';
import { type Website } from '@site/data/website';
import Tooltip from '../../../project/_components/ShowcaseTooltip';

const WebsiteCard = memo(({ website }: { website: Website }) => (
  <li
    key={website.name}
    className={clsx(styles.websiteCard, 'padding-vert--sm padding-horiz--md')}
  >
    <img
      src={
        typeof website.logo === 'string'
          ? website.logo
          : (website.logo as any)?.src?.src
      }
      alt={website.name}
      className={clsx(styles.websiteCardImage)}
    />
    <div className={styles.websiteCardBody}>
      <div className={clsx(styles.websiteCardHeader)}>
        <h4 className={styles.websiteCardTitle}>
          <Link href={website.href} className={styles.websiteCardLink}>
            {website.name}
          </Link>
        </h4>
      </div>
      <Tooltip
        key={website.name}
        text={website.desc}
        anchorEl="#__docusaurus"
        id={`tooltip-${website.name}`}
      >
        <p className={styles.websiteCardDesc}>{website.desc}</p>
      </Tooltip>
    </div>
  </li>
));

export default WebsiteCard;
