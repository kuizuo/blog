import { translate } from '@docusaurus/Translate'
import { useThemeConfig } from '@docusaurus/theme-common'
import { useHideableNavbar, useNavbarMobileSidebar } from '@docusaurus/theme-common/internal'
import type { Props } from '@theme/Navbar/Layout'
import NavbarMobileSidebar from '@theme/Navbar/MobileSidebar'
import clsx from 'clsx'
import { useMotionValueEvent, useScroll } from 'motion/react'
import { type ComponentProps, useEffect, useState } from 'react'
import { NavbarCompactContext } from '../CompactContext'

import styles from './styles.module.css'

const COMPACT_ENTER_Y = 160
const COMPACT_EXIT_Y = 48

function NavbarBackdrop(props: ComponentProps<'div'>) {
  return <div role="presentation" {...props} className={clsx('navbar-sidebar__backdrop', props.className)} />
}

export default function NavbarLayout({ children }: Props): JSX.Element {
  const {
    navbar: { hideOnScroll, style },
  } = useThemeConfig()
  const mobileSidebar = useNavbarMobileSidebar()
  const { navbarRef, isNavbarVisible } = useHideableNavbar(hideOnScroll)
  const { scrollY } = useScroll()
  const [compact, setCompact] = useState(false)

  useEffect(() => {
    setCompact(window.scrollY > COMPACT_ENTER_Y)
  }, [])

  useMotionValueEvent(scrollY, 'change', (y) => {
    const next = y > (compact ? COMPACT_EXIT_Y : COMPACT_ENTER_Y)
    if (next !== compact) setCompact(next)
  })

  return (
    <nav
      ref={navbarRef}
      data-compact={compact}
      aria-label={translate({
        id: 'theme.NavBar.navAriaLabel',
        message: 'Main',
        description: 'The ARIA label for the main navigation',
      })}
      className={clsx(
        'navbar',
        'navbar--fixed-top',
        'bg-transparent',
        styles.navbar,
        hideOnScroll && [styles.navbarHideable, !isNavbarVisible && styles.navbarHidden],
        {
          'navbar--dark': style === 'dark',
          'navbar--primary': style === 'primary',
          'navbar-sidebar--show': mobileSidebar.shown,
        },
      )}
    >
      <NavbarCompactContext.Provider value={compact}>
        {children}
      </NavbarCompactContext.Provider>
      <NavbarBackdrop onClick={mobileSidebar.toggle} />
      <NavbarMobileSidebar />
    </nav>
  )
}
