import { translate } from '@docusaurus/Translate'
import { useThemeConfig } from '@docusaurus/theme-common'
import { useHideableNavbar, useNavbarMobileSidebar } from '@docusaurus/theme-common/internal'
import type { Props } from '@theme/Navbar/Layout'
import NavbarMobileSidebar from '@theme/Navbar/MobileSidebar'
import clsx from 'clsx'
import { type ComponentProps } from 'react'
import { useLocation } from 'react-router-dom'

import styles from './styles.module.css'

function NavbarBackdrop(props: ComponentProps<'div'>) {
  return <div role="presentation" {...props} className={clsx('navbar-sidebar__backdrop', props.className)} />
}

export default function NavbarLayout({ children }: Props): JSX.Element {
  const {
    navbar: { hideOnScroll, style },
  } = useThemeConfig()
  const mobileSidebar = useNavbarMobileSidebar()
  const { navbarRef, isNavbarVisible } = useHideableNavbar(hideOnScroll)

  const location = useLocation()
  const isHomePage = location.pathname === '/' || location.pathname === '/en/'

  return (
    <nav
      ref={navbarRef}
      aria-label={translate({
        id: 'theme.NavBar.navAriaLabel',
        message: 'Main',
        description: 'The ARIA label for the main navigation',
      })}
      className={clsx(
        'navbar',
        'navbar--fixed-top',
        isHomePage && 'bg-transparent',
        hideOnScroll && [styles.navbarHideable, !isNavbarVisible && styles.navbarHidden],
        {
          'navbar--dark': style === 'dark',
          'navbar--primary': style === 'primary',
          'navbar-sidebar--show': mobileSidebar.shown,
        },
      )}
    >
      {children}
      <NavbarBackdrop onClick={mobileSidebar.toggle} />
      <NavbarMobileSidebar />
    </nav>
  )
}
