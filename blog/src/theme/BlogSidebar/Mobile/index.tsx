import React from 'react'
import Link from '@docusaurus/Link'
import { NavbarSecondaryMenuFiller } from '@docusaurus/theme-common'
import type { Props } from '@theme/BlogSidebar/Mobile'

function BlogSidebarMobileSecondaryMenu({ sidebar }: Props): JSX.Element {
  return (
    <ul className="menu__list">
      {sidebar.items.map(item => (
        <li key={item.permalink} className="menu__list-item">
          <Link
            isNavLink
            to={item.permalink}
            className="menu__link"
            activeClassName="menu__link--active"
          >
            {item.title}
          </Link>
        </li>
      ))}
    </ul>
  )
}

export default function BlogSidebarMobile(props: Props): JSX.Element {
  return (
    <NavbarSecondaryMenuFiller
      component={BlogSidebarMobileSecondaryMenu}
      props={props}
    />
  )
}
