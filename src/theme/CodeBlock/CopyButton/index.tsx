import { translate } from '@docusaurus/Translate'
import { cn } from '@site/src/lib/utils'
import type { Props } from '@theme/CodeBlock/CopyButton'
import IconCopy from '@theme/Icon/Copy'
import IconSuccess from '@theme/Icon/Success'
import copy from 'copy-text-to-clipboard'
import React, { useCallback, useState, useRef, useEffect } from 'react'

import styles from './styles.module.css'

export default function CopyButton({ code, className }: Props): JSX.Element {
  const [isCopied, setIsCopied] = useState(false)
  const copyTimeout = useRef<number | undefined>(undefined)
  const handleCopyCode = useCallback(() => {
    copy(code)
    setIsCopied(true)
    copyTimeout.current = window.setTimeout(() => {
      setIsCopied(false)
    }, 1000)
  }, [code])

  useEffect(() => () => window.clearTimeout(copyTimeout.current), [])

  return (
    <button
      type="button"
      aria-label={
        isCopied
          ? translate({
              id: 'theme.CodeBlock.copied',
              message: 'Copied',
              description: 'The copied button label on code blocks',
            })
          : translate({
              id: 'theme.CodeBlock.copyButtonAriaLabel',
              message: 'Copy code to clipboard',
              description: 'The ARIA label for copy code blocks button',
            })
      }
      title={translate({
        id: 'theme.CodeBlock.copy',
        message: 'Copy',
        description: 'The copy button label on code blocks',
      })}
      className={cn('clean-btn', className, styles.copyButton, isCopied && styles.copyButtonCopied)}
      onClick={handleCopyCode}
    >
      <span className={styles.copyButtonIcons} aria-hidden="true">
        <IconCopy className={styles.copyButtonIcon} />
        <IconSuccess className={styles.copyButtonSuccessIcon} />
      </span>
    </button>
  )
}
