import React from 'react'
import Link from '@docusaurus/Link'
import type { Props } from '@theme/MDXComponents/A'

import { Icon } from '@iconify/react'

export default function MDXA(props: Props): JSX.Element {
  const href = props.href

  if (!href) return <Link {...props} />

  const iconMappings = {
    'github.com': 'simple-icons:github',
    'twitter.com': 'logos:twitter',
  }

  const foundKey = Object.keys(iconMappings).find(key => {
    const prefixRegex = new RegExp(`^https?://${key}`)
    return prefixRegex.test(href)
  })

  const icon = foundKey ? iconMappings[foundKey] : null

  if (icon) {
    return (
      <span style={{ display: 'inline-flex', gap: '0.25rem' }}>
        {icon && (
          <Icon
            className="a-icon"
            style={{ alignSelf: 'center' }}
            icon={icon}
            width={16}
            height={16}
          ></Icon>
        )}
        <Link {...props} />
      </span>
    )
  }

  return <Link {...props} />
}
