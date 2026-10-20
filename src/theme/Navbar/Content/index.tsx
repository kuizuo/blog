import { ErrorCauseBoundary, useThemeConfig } from '@docusaurus/theme-common'
import { useLocation } from '@docusaurus/router'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import { splitNavbarItems, useNavbarMobileSidebar } from '@docusaurus/theme-common/internal'
import NavbarColorModeToggle from '@theme/Navbar/ColorModeToggle'
import NavbarLogo from '@theme/Navbar/Logo'
import NavbarMobileSidebarToggle from '@theme/Navbar/MobileSidebar/Toggle'
import NavbarSearch from '@theme/Navbar/Search'
import NavbarItem, { type Props as NavbarItemConfig } from '@theme/NavbarItem'
import SearchBar from '@theme/SearchBar'
import { LayoutGroup, motion, type Transition, useReducedMotion } from 'motion/react'
import React, { type ReactNode, useContext, useEffect, useId, useRef, useState } from 'react'
import { NavbarCompactContext } from '../CompactContext'

import styles from './styles.module.css'

const layoutTransition: Transition = { duration: 0.35, ease: [0.16, 1, 0.3, 1] }

function useNavbarItems() {
  // TODO temporary casting until ThemeConfig type is improved
  return useThemeConfig().navbar.items as NavbarItemConfig[]
}

function NavbarItems({ items }: { items: NavbarItemConfig[] }): JSX.Element {
  return (
    <>
      {items.map((item, i) => (
        <ErrorCauseBoundary
          key={i}
          onError={error =>
            new Error(
              `A theme navbar item failed to render.
Please double-check the following navbar item (themeConfig.navbar.items) of your Docusaurus config:
${JSON.stringify(item, null, 2)}`,
              { cause: error },
            )}
        >
          <NavbarItem {...item} />
        </ErrorCauseBoundary>
      ))}
    </>
  )
}

function DesktopNavbarItems({ items }: { items: NavbarItemConfig[] }) {
  const { pathname } = useLocation()
  const root = useRef<HTMLDivElement>(null)
  const [active, setActive] = useState<number | null>(null)
  const [hovered, setHovered] = useState<number | null>(null)
  const reduceMotion = useReducedMotion()
  const id = useId()

  useEffect(() => {
    setHovered(null)
    const current = root.current?.querySelector('.navbar__link--active, .dropdown__link--active')
    const item = current?.closest<HTMLElement>('[data-nav-index]')
    setActive(item ? Number(item.dataset.navIndex) : null)
  }, [pathname])

  return (
    <LayoutGroup id={id}>
      <div
        ref={root}
        className={styles.navigation}
        onPointerLeave={() => setHovered(null)}
        onBlurCapture={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget)) setHovered(null)
        }}
      >
        {items.map((item, index) => (
          <div
            key={index}
            className={styles.navItem}
            data-nav-index={index}
            onPointerEnter={() => setHovered(index)}
            onFocusCapture={() => setHovered(index)}
          >
            <NavbarItems items={[item]} />
            {(hovered ?? active) === index && (
              <motion.span
                aria-hidden="true"
                className={styles.indicator}
                layoutId="navbar-indicator"
                initial={false}
                transition={{ duration: reduceMotion ? 0 : 0.28, ease: [0.16, 1, 0.3, 1] }}
              />
            )}
          </div>
        ))}
      </div>
    </LayoutGroup>
  )
}

function NavbarContentLayout({
  left,
  right,
}: {
  left: ReactNode
  right: ReactNode
}) {
  const reduceMotion = useReducedMotion()
  const compact = useContext(NavbarCompactContext)

  return (
    <motion.div
      className={`navbar__inner ${styles.inner}`}
      layout={reduceMotion ? false : 'position'}
      layoutDependency={compact}
      transition={layoutTransition}
    >
      <motion.div layout={reduceMotion ? false : 'position'} transition={layoutTransition} className={`navbar__items ${styles.leading}`}>{left}</motion.div>
      <motion.div layout={reduceMotion ? false : 'position'} transition={layoutTransition} className={`navbar__items navbar__items--right ${styles.trailing}`}>{right}</motion.div>
    </motion.div>
  )
}

export default function NavbarContent(): JSX.Element {
  const { siteConfig: { title } } = useDocusaurusContext()
  const mobileSidebar = useNavbarMobileSidebar()

  const items = useNavbarItems()
  const [leftItems, rightItems] = splitNavbarItems(items)

  const searchBarItem = items.find(item => item.type === 'search')

  return (
    <NavbarContentLayout
      left={(
        // TODO stop hardcoding items?
        <>
          {!mobileSidebar.disabled && <NavbarMobileSidebarToggle />}
          <div className={styles.brand}>
            <NavbarLogo />
            <span className={styles.brandName} aria-hidden="true">{title}</span>
          </div>
          <DesktopNavbarItems items={leftItems} />
        </>
      )}
      right={(
        // TODO stop hardcoding items?
        // Ask the user to add the respective navbar items => more flexible
        <>
          <DesktopNavbarItems items={rightItems} />
          <div className={styles.actions}>
            <NavbarColorModeToggle className={styles.colorModeToggle} />
            {!searchBarItem && (
              <NavbarSearch>
                <SearchBar />
              </NavbarSearch>
            )}
          </div>
        </>
      )}
    />
  )
}
