import Link from '@docusaurus/Link'
import clsx from 'clsx'
import React, { memo } from 'react'

import type { Friend } from '@site/data/friends'
import styles from './styles.module.css'

const FriendCard = memo(({ friend }: { friend: Friend }) => (
  <li className={clsx(styles.friendCard, 'padding-vert--sm padding-horiz--md')}>
    <img
      src={typeof friend.avatar === 'string' ? friend.avatar : friend.avatar.src.src}
      alt={friend.title}
      className={clsx(styles.friendCardImage)}
    />
    <div className="card__body">
      <div className={clsx(styles.friendCardHeader)}>
        <h4 className={styles.friendCardTitle}>
          <Link to={friend.website} className={styles.friendCardLink} rel="">
            {friend.title}
          </Link>
        </h4>
      </div>
      <p className={styles.friendCardDesc}>{friend.description}</p>
    </div>
  </li>
))

export default FriendCard
