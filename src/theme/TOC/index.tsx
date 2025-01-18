import { useReadPercent } from '@site/src/hooks/useReadPercent'
import { cn } from '@site/src/lib/utils'
import type { Props } from '@theme/TOC'
import TOCItems from '@theme/TOCItems'
import { motion } from 'framer-motion'
import styles from './styles.module.css'

const LINK_CLASS_NAME = 'table-of-contents__link toc-highlight'
const LINK_ACTIVE_CLASS_NAME = 'table-of-contents__link--active'

export default function TOC({ className, ...props }: Props): JSX.Element {
  const { readPercent } = useReadPercent()

  return (
    <motion.div
      className={cn(styles.tableOfContents, 'thin-scrollbar', className)}
      initial={{ opacity: 0.0001, x: 100 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{
        type: 'spring',
        stiffness: 400,
        damping: 20,
        duration: 3,
      }}
    >
      <TOCItems
        {...props}
        className="table-of-contents pl-0"
        linkClassName={LINK_CLASS_NAME}
        linkActiveClassName={LINK_ACTIVE_CLASS_NAME}
      />
      <hr className={styles.hr} />
      <span className={styles.percent}>
        {`${readPercent}%`}
        {' '}
      </span>
    </motion.div>
  )
}
