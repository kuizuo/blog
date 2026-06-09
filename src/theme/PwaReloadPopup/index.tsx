import Translate, { translate } from '@docusaurus/Translate'
import { cn } from '@site/src/lib/utils'
import { useState, type ReactNode } from 'react'

import styles from './styles.module.css'

type Props = {
  onReload: () => void
}

export default function PwaReloadPopup({ onReload }: Props): ReactNode {
  const [isVisible, setIsVisible] = useState(true)

  return isVisible
    ? (
        <div className={cn('alert', 'alert--secondary', styles.popup)}>
          <p>
            <Translate id="theme.PwaReloadPopup.info" description="The text for PWA reload popup">
              New version available
            </Translate>
          </p>
          <div className={styles.buttonContainer}>
            <button
              className="button button--link"
              type="button"
              onClick={() => {
                setIsVisible(false)
                onReload()
              }}
            >
              <Translate id="theme.PwaReloadPopup.refreshButtonText" description="The text for PWA reload button">
                Refresh
              </Translate>
            </button>

            <button
              aria-label={translate({
                id: 'theme.PwaReloadPopup.closeButtonAriaLabel',
                message: 'Close',
                description: 'The ARIA label for close button of PWA reload popup',
              })}
              className="close"
              type="button"
              onClick={() => setIsVisible(false)}
            >
              <span aria-hidden="true">x</span>
            </button>
          </div>
        </div>
      )
    : null
}
