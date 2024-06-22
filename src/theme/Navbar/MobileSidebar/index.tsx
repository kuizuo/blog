import { useLockBodyScroll, useNavbarMobileSidebar } from '@docusaurus/theme-common/internal'
import NavbarMobileSidebarHeader from '@theme/Navbar/MobileSidebar/Header'
import NavbarMobileSidebarLayout from '@theme/Navbar/MobileSidebar/Layout'
import NavbarMobileSidebarPrimaryMenu from '@theme/Navbar/MobileSidebar/PrimaryMenu'
import NavbarMobileSidebarSecondaryMenu from '@theme/Navbar/MobileSidebar/SecondaryMenu'
import React from 'react'

export default function NavbarMobileSidebar(): JSX.Element | null {
  const mobileSidebar = useNavbarMobileSidebar()
  useLockBodyScroll(mobileSidebar.shown)

  if (!mobileSidebar.shouldRender) {
    return null
  }

  return (
    <NavbarMobileSidebarLayout
      header={<NavbarMobileSidebarHeader />}
      primaryMenu={<NavbarMobileSidebarPrimaryMenu />}
      secondaryMenu={<NavbarMobileSidebarSecondaryMenu />}
    />
  )
}
