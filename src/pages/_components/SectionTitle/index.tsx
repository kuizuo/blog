import Link from '@docusaurus/Link'
import Translate from '@docusaurus/Translate'
import { Icon } from '@iconify/react'
import type React from 'react'

interface Props {
  icon?: string
  href?: string
  children: React.ReactNode
}

export default function SectionTitle({ children, icon, href }: Props) {
  return (
    <div
      className={'mt-8 mb-4 inline-flex w-full items-center justify-between px-[var(--ifm-spacing-horizontal)] md:mt-6'}
    >
      <h2 className="m-0 inline-flex items-center justify-center gap-1 text-lg">
        {icon && <Icon icon={icon} />}
        {children}
      </h2>
      {href && (
        <Link href={href} className="inline-flex items-center justify-center text-base hover:no-underline">
          <Translate id="homepage.lookMore">查看更多</Translate>
          <Icon icon="ri:arrow-right-s-line" />
        </Link>
      )}
    </div>
  )
}
