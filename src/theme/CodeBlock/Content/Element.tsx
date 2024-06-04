import { cn } from '@site/src/lib/utils'
import Container from '@theme/CodeBlock/Container'
import type { Props } from '@theme/CodeBlock/Content/Element'
import React from 'react'

import styles from './styles.module.css'

// <pre> tags in markdown map to CodeBlocks. They may contain JSX children. When
// the children is not a simple string, we just return a styled block without
// actually highlighting.
export default function CodeBlockJSX({ children, className }: Props): JSX.Element {
  return (
    <Container as="pre" tabIndex={0} className={cn(styles.codeBlockStandalone, 'thin-scrollbar', className)}>
      <code className={styles.codeBlockLines}>{children}</code>
    </Container>
  )
}
