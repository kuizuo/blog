import React from 'react'
import clsx from 'clsx'
import { motion } from 'framer-motion'
import TOCItems from '@theme/TOCItems'
import type { Props } from '@theme/TOC'
import styles from './styles.module.css'
import { useReadPercent } from '@site/src/hooks/useReadPercent'

const LINK_CLASS_NAME = 'table-of-contents__link toc-highlight'
const LINK_ACTIVE_CLASS_NAME = 'table-of-contents__link--active'

export default function TOC({ className, ...props }: Props): JSX.Element {
  const { readPercent } = useReadPercent()

  return (
    <motion.div
      className={clsx(styles.tableOfContents, 'thin-scrollbar', className)}
      initial={{ opacity: 0, x: 100 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{
        type: 'spring',
        stiffness: 400,
        damping: 20,
        duration: 0.3,
      }}
    >
      <TOCItems
        {...props}
        linkClassName={LINK_CLASS_NAME}
        linkActiveClassName={LINK_ACTIVE_CLASS_NAME}
      />
      <hr className={styles.hr} />
      <span className={styles.percent}>{readPercent + '%'} </span>
    </motion.div>
  )
}
