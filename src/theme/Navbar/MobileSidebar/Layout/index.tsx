import { useNavbarSecondaryMenu } from '@docusaurus/theme-common/internal'
import UserCard from '@site/src/components/UserCard'
import type { Props } from '@theme/Navbar/MobileSidebar/Layout'
import clsx from 'clsx'
import React from 'react'

export default function NavbarMobileSidebarLayout({ header, primaryMenu, secondaryMenu }: Props): JSX.Element {
  const { shown: secondaryMenuShown } = useNavbarSecondaryMenu()
  return (
    <div className="navbar-sidebar">
      {header}
      <UserCard isNavbar />
      <div
        className={clsx('navbar-sidebar__items', {
          'navbar-sidebar__items--show-secondary': secondaryMenuShown,
        })}
      >
        <div className="navbar-sidebar__item menu">{primaryMenu}</div>
        <div className="navbar-sidebar__item menu">{secondaryMenu}</div>
      </div>
    </div>
  )
}
